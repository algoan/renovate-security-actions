import json
import subprocess

import pytest

from renovate_security.ecosystems import Docker, Npm, Pnpm, Poetry, ReplayError, Upstream, Uv, select
from renovate_security.ecosystems import npm as npm_module
from renovate_security.ecosystems.docker import image_refs, split_ref
from renovate_security.ecosystems.python import direct_poetry_dependencies
from renovate_security.ecosystems.upstream import parse_cpes, pinned_sources
from renovate_security.versions import loose_key

POETRY_LOCK = """
[[package]]
name = "urllib3"
version = "2.2.1"

[[package]]
name = "requests"
version = "2.32.3"

[metadata]
lock-version = "2.0"
"""

PACKAGE_LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "^4.18.0"}},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/qs": {"version": "6.11.0"},
        "node_modules/body-parser/node_modules/qs": {"version": "6.10.3"},
        "node_modules/@scope/pkg": {"version": "1.0.0"},
        "node_modules/local": {"link": True, "resolved": "../local"},
    },
}

PACKAGE_LOCK_V1 = {
    "lockfileVersion": 1,
    "dependencies": {
        "express": {
            "version": "4.17.1",
            "dependencies": {"qs": {"version": "6.7.0"}},
        },
        "mine": {"version": "file:../mine"},
    },
}

DOCKERFILE = """\
FROM golang:1.27.2-bookworm AS sigil-builder
RUN go build
FROM --platform=linux/amd64 nvidia/cuda:12.6.3-cudnn-runtime-ubuntu24.04@sha256:aaa AS base
FROM base
FROM scratch
FROM ${BASE_IMAGE}
FROM ubuntu
COPY --from=ghcr.io/astral-sh/uv:0.12.24@sha256:bbb /uv /uvx /bin/
COPY --from=sigil-builder /go/bin/sigil /usr/bin/sigil
COPY --chown=1000 --from=localhost:5000/tools@sha256:ccc /x /y

# renovate: datasource=github-tags depName=openssl/openssl extractVersion=^openssl-(?<version>.+)$
ENV OPENSSL_VERSION=3.6.5
# renovate: datasource=docker depName=nginx cpe=f5:nginx
ENV NGINX_VERSION=1.31.6
# renovate: datasource=github-tags depName=openresty/luajit2 versioning=regex:^(?<major>\\d+)\\.(?<minor>\\d+)-(?<patch>\\d+)$

ARG LUAJIT_VERSION=2.1-20250826
# renovate: datasource=github-releases depName=DataDog/nginx-datadog
ENV DD_NGINX_VERSION v1.25.1
# renovate: not a pin
RUN echo
"""


def test_poetry_parses_its_lockfile():
    assert Poetry().parse({"poetry.lock": POETRY_LOCK}) == {
        "urllib3": {"2.2.1"},
        "requests": {"2.32.3"},
    }


def test_uv_merges_several_lockfiles():
    lock = '[[package]]\nname = "ray"\nversion = "2.52.1"\n'
    other = '[[package]]\nname = "ray"\nversion = "2.56.0"\n'
    assert Uv().parse({"a/uv.lock": lock, "b/uv.lock": other}) == {"ray": {"2.52.1", "2.56.0"}}


def test_npm_parses_v3_lockfiles_with_nested_versions():
    assert Npm().parse({"package-lock.json": json.dumps(PACKAGE_LOCK_V3)}) == {
        "express": {"4.18.2"},
        "qs": {"6.11.0", "6.10.3"},
        "@scope/pkg": {"1.0.0"},
    }


@pytest.mark.parametrize(
    ("before", "after", "level"),
    [
        ("1.2.3", "1.2.4", "patch"),
        ("1.2.3", "1.2.3-1", "minor"),  # prerelease of the same version: a downgrade
        ("1.2.3-rc.1", "1.2.3", "patch"),
        ("1.2.3-rc.2", "1.2.3-rc.10", "patch"),
        ("1.2.3", "1.3.0", "minor"),
    ],
)
def test_npm_levels_follow_semver_prereleases(before, after, level):
    assert Npm().level({before}, {after}) == level


def test_npm_parses_v1_lockfiles():
    assert Npm().parse({"package-lock.json": json.dumps(PACKAGE_LOCK_V1)}) == {
        "express": {"4.17.1"},
        "qs": {"6.7.0"},
    }


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("nginx:1.27", ("nginx", "1.27")),
        ("nginx:1.27@sha256:abc", ("nginx", "1.27@sha256:abc")),
        ("nginx@sha256:abc", ("nginx", "@sha256:abc")),
        ("localhost:5000/tools:1.0", ("localhost:5000/tools", "1.0")),
        ("localhost:5000/tools", None),
        ("ubuntu", None),
        ("scratch", None),
        ("${IMAGE}:1.0", None),
    ],
)
def test_split_ref(ref, expected):
    assert split_ref(ref) == expected


def test_docker_lists_pinned_images_but_not_stages():
    assert image_refs(DOCKERFILE) == [
        ("golang", "1.27.2-bookworm"),
        ("nvidia/cuda", "12.6.3-cudnn-runtime-ubuntu24.04@sha256:aaa"),
        ("ghcr.io/astral-sh/uv", "0.12.24@sha256:bbb"),
        ("localhost:5000/tools", "@sha256:ccc"),
    ]


@pytest.mark.parametrize(
    ("before", "after", "level"),
    [
        ("12.6.3-cudnn-runtime-ubuntu24.04@sha256:a", "12.6.3-cudnn-runtime-ubuntu24.04@sha256:b", "digest"),
        ("12.6.3-cudnn-runtime-ubuntu24.04@sha256:a", "12.6.4-cudnn-runtime-ubuntu24.04@sha256:b", "patch"),
        ("12.6.3-cudnn-runtime-ubuntu24.04@sha256:a", "12.9.2-cudnn-runtime-ubuntu24.04@sha256:b", "minor"),
        ("12.6.3-cudnn-runtime-ubuntu24.04", "13.0.0-cudnn-runtime-ubuntu24.04", "major"),
        ("3.20-alpine", "3.20-slim", "major"),
        ("0.12.24@sha256:a", "0.13.0@sha256:b", "minor"),
        ("1.27", "1.27", "none"),
    ],
)
def test_docker_levels(before, after, level):
    assert Docker().level({before}, {after}) == level


def test_upstream_reads_renovate_pins():
    pins = pinned_sources(DOCKERFILE)
    assert [(fields["depName"], value) for fields, value, _ in pins] == [
        ("openssl/openssl", "3.6.5"),
        ("nginx", "1.31.6"),
        ("openresty/luajit2", "2.1-20250826"),
        ("DataDog/nginx-datadog", "v1.25.1"),
    ]


def test_upstream_collects_cpes_from_comments_and_input():
    upstream = Upstream()
    upstream.parse({"Dockerfile": DOCKERFILE})
    assert upstream.cpes == {"nginx": "f5:nginx"}
    assert parse_cpes("openssl/openssl=openssl:openssl\n\nbad line\n nginx = f5:nginx ") == {
        "openssl/openssl": "openssl:openssl",
        "nginx": "f5:nginx",
    }


@pytest.mark.parametrize(
    ("before", "after", "level"),
    [
        ("2.1-20250826", "2.1-20251010", "patch"),
        ("3.6.5", "3.6.6", "patch"),
        ("3.6.5", "4.0.0", "major"),
        ("v1.25.1", "v1.26.0", "minor"),
        ("2.1.0.19", "2.1.0.20", "patch"),
    ],
)
def test_upstream_levels(before, after, level):
    assert Upstream().level({before}, {after}) == level


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.2.3-rc.1", "1.2.3"),
        ("1.2.3-alpha.2", "1.2.3-alpha.10"),
        ("v1.9.0", "1.10.0"),
        ("2.1-20250826", "2.1-20251010"),
    ],
)
def test_loose_key_orders_versions(lower, higher):
    assert loose_key(lower) < loose_key(higher)


def test_select_detects_ecosystems_from_files():
    names = [e.name for e in select("auto", ["uv.lock", "pyproject.toml", "build/Dockerfile"])]
    assert names == ["uv", "docker", "upstream"]
    assert [e.name for e in select("npm, uv", [])] == ["npm", "uv"]
    with pytest.raises(ValueError):
        select("cargo", [])


def test_direct_poetry_dependencies():
    pyproject = {
        "project": {"dependencies": ["requests>=2.31", "Flask[async] (>=3.0)"]},
        "tool": {
            "poetry": {
                "dependencies": {"python": "^3.12", "pydantic": "^2"},
                "group": {"dev": {"dependencies": {"pytest": "^8"}}},
            }
        },
    }
    assert direct_poetry_dependencies(pyproject) == {"requests", "flask", "pydantic", "pytest"}


def git_repo(tmp_path, files):
    for path, content in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def test_docker_replay_rewrites_only_the_pinned_image(tmp_path):
    root = git_repo(tmp_path, {"Dockerfile": DOCKERFILE})
    Docker().replay(root, [("nvidia/cuda", "12.6.4-cudnn-runtime-ubuntu24.04@sha256:new")])
    text = (root / "Dockerfile").read_text()
    assert "FROM --platform=linux/amd64 nvidia/cuda:12.6.4-cudnn-runtime-ubuntu24.04@sha256:new AS base" in text
    assert text.replace("12.6.4-cudnn-runtime-ubuntu24.04@sha256:new", "12.6.3-cudnn-runtime-ubuntu24.04@sha256:aaa") == DOCKERFILE


def test_docker_replay_fails_on_unknown_image(tmp_path):
    root = git_repo(tmp_path, {"Dockerfile": DOCKERFILE})
    with pytest.raises(ReplayError):
        Docker().replay(root, [("redis", "7.4")])


def test_upstream_replay_rewrites_the_pinned_value(tmp_path):
    root = git_repo(tmp_path, {"Dockerfile": DOCKERFILE})
    Upstream().replay(root, [("openssl/openssl", "3.6.6"), ("DataDog/nginx-datadog", "v1.26.0")])
    text = (root / "Dockerfile").read_text()
    assert "ENV OPENSSL_VERSION=3.6.6\n" in text
    assert "ENV DD_NGINX_VERSION v1.26.0\n" in text
    with pytest.raises(ReplayError):
        Upstream().replay(root, [("unknown/dep", "1.0")])


def test_npm_replay_pins_direct_and_overrides_transitive(tmp_path, monkeypatch):
    manifest = {"name": "app", "dependencies": {"express": "^4.18.0"}}
    root = git_repo(
        tmp_path,
        {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(PACKAGE_LOCK_V3)},
    )
    calls = []
    monkeypatch.setattr(npm_module, "run", lambda cmd, cwd, env=None: calls.append(cmd))
    Npm().replay(root, [("express", "4.21.2"), ("qs", "6.14.1")])
    assert calls[0][-2:] == ["--save-exact", "express@4.21.2"]
    assert json.loads((root / "package.json").read_text())["overrides"] == {"qs": "6.14.1"}
    assert len(calls) == 2


def test_poetry_replay_refuses_transitive_dependencies(tmp_path):
    root = git_repo(
        tmp_path,
        {
            "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "^2"\n',
            "poetry.lock": POETRY_LOCK,
        },
    )
    with pytest.raises(ReplayError, match="urllib3"):
        Poetry().replay(root, [("urllib3", "2.2.2")])


def test_legacy_poetry_dev_dependencies_are_direct():
    pyproject = {"tool": {"poetry": {"dev-dependencies": {"pytest": "^7"}}}}
    assert direct_poetry_dependencies(pyproject) == {"pytest"}


def test_tokenless_env_drops_secrets_whatever_their_case(monkeypatch):
    from renovate_security.ecosystems.python import tokenless_env

    for name in ("github_token", "clientSecret", "NPM_AUTH", "password", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.setenv(name, "x")
    monkeypatch.setenv("HOME_DIR", "kept")
    env = tokenless_env()
    assert env["HOME_DIR"] == "kept"
    assert not {"github_token", "clientSecret", "NPM_AUTH", "password", "GOOGLE_APPLICATION_CREDENTIALS"} & set(env)


def test_replay_stays_in_its_project(tmp_path):
    lock = '[[package]]\nname = "x"\nversion = "1"\n'
    root = git_repo(
        tmp_path,
        {"a/Dockerfile": "FROM nginx:1.27\n", "b/Dockerfile": "FROM nginx:1.27\n", "a/uv.lock": lock},
    )
    Docker().replay(root / "a", [("nginx", "1.27.1")])
    assert (root / "a/Dockerfile").read_text() == "FROM nginx:1.27.1\n"
    assert (root / "b/Dockerfile").read_text() == "FROM nginx:1.27\n"


def test_docker_replay_fails_when_one_image_is_missing(tmp_path):
    root = git_repo(tmp_path, {"Dockerfile": DOCKERFILE})
    with pytest.raises(ReplayError, match="redis"):
        Docker().replay(root, [("golang", "1.27.3-bookworm"), ("redis", "7.4")])


@pytest.mark.parametrize(
    ("path", "owned"),
    [
        ("Dockerfile", True),
        ("build/dockerfile.prod", True),
        ("api.Dockerfile", True),
        ("service.Dockerfile.dev", True),
        ("Dockerfile.md", True),
        ("docs/dockerfiles.md", False),
        ("Dockerfile-old", False),
    ],
)
def test_dockerfile_names_match_the_action_detection(path, owned):
    assert Docker().owns(path) is owned
    assert Upstream().owns(path) is owned
    assert [e.name for e in select("auto", [path])] == (["docker", "upstream"] if owned else [])


def test_upstream_cpe_of_the_head_wins():
    upstream = Upstream()
    old = "# renovate: datasource=docker depName=nginx cpe=nginx:nginx\nENV V=1.0\n"
    new = "# renovate: datasource=docker depName=nginx cpe=f5:nginx\nENV V=1.0\n"
    upstream.parse({"Dockerfile": old})
    upstream.parse({"Dockerfile": new})
    assert upstream.cpes == {"nginx": "f5:nginx"}


def test_upstream_cpe_removed_by_the_head_is_dropped():
    upstream = Upstream()
    upstream.parse({"Dockerfile": "# renovate: datasource=docker depName=nginx cpe=f5:nginx\nENV V=1.0\n"})
    upstream.parse({"Dockerfile": "# renovate: datasource=docker depName=nginx\nENV V=1.1\n"})
    assert upstream.cpes == {}


def test_direct_poetry_dependencies_use_pep503_names():
    pyproject = {"tool": {"poetry": {"dependencies": {"typing_extensions": "^4", "Zope.Interface": "*"}}}}
    assert direct_poetry_dependencies(pyproject) == {"typing-extensions", "zope-interface"}


PNPM_LOCK_V9 = """\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      '@nestjs/common':
        specifier: ^11.0.0
        version: 11.2.7(reflect-metadata@0.2.2)(rxjs@7.8.1)
      axios:
        specifier: ^1.7.9
        version: 1.18.1

packages:

  '@nestjs/common@11.2.7':
    resolution: {integrity: sha512-aaa}
    peerDependencies:
      rxjs: ^7.1.0

  axios@1.18.1:
    resolution: {integrity: sha512-bbb}

  qs@6.14.0:
    resolution: {integrity: sha512-ccc}

snapshots:

  '@nestjs/common@11.2.7(reflect-metadata@0.2.2)(rxjs@7.8.1)':
    dependencies:
      rxjs: 7.8.1

  axios@1.18.1: {}
"""

PNPM_LOCK_V6 = """\
lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2

packages:

  /@scope/pkg@1.0.0(peer@2.0.0):
    resolution: {integrity: sha512-aaa}
    dev: false

  /express@4.18.2:
    resolution: {integrity: sha512-bbb}
    dev: false

  /qs@6.11.0:
    resolution: {integrity: sha512-ccc}
"""

PNPM_LOCK_V5 = """\
lockfileVersion: 5.4

packages:

  /@scope/pkg/1.0.0:
    resolution: {integrity: sha512-aaa}

  /express/4.17.1_qs@6.7.0:
    resolution: {integrity: sha512-bbb}
"""


def test_pnpm_parses_a_v9_lockfile():
    assert Pnpm().parse({"pnpm-lock.yaml": PNPM_LOCK_V9}) == {
        "@nestjs/common": {"11.2.7"},
        "axios": {"1.18.1"},
        "qs": {"6.14.0"},
    }


def test_pnpm_parses_v6_and_v5_lockfiles():
    assert Pnpm().parse({"pnpm-lock.yaml": PNPM_LOCK_V6}) == {
        "@scope/pkg": {"1.0.0"},
        "express": {"4.18.2"},
        "qs": {"6.11.0"},
    }
    assert Pnpm().parse({"pnpm-lock.yaml": PNPM_LOCK_V5}) == {
        "@scope/pkg": {"1.0.0"},
        "express": {"4.17.1"},
    }


PNPM_LOCK_REGISTRY_QUALIFIED = """\
lockfileVersion: '6.0'

packages:

  registry.example.com/@scope/pkg@1.0.0:
    resolution: {integrity: sha512-aaa}

  registry.npmjs.org/axios@1.6.0(debug@4.3.4):
    resolution: {integrity: sha512-bbb}

  /registry.node-modules.io/foo@2.0.0:
    resolution: {integrity: sha512-ccc}

  registry.npmjs.org/bar/3.0.0:
    resolution: {integrity: sha512-ddd}

  /lodash.merge/4.6.2:
    resolution: {integrity: sha512-eee}

  lodash.merge@4.6.3:
    resolution: {integrity: sha512-fff}

  '@scope/aliased@work:5.0.0':
    resolution: {integrity: sha512-ggg}

  node@runtime:24.6.0:
    resolution: {type: nodeRuntime}
"""


def test_pnpm_strips_the_registry_host_of_registry_qualified_keys():
    # Packages from a non-default registry are keyed by their host (or a named alias in the version);
    # a dotted package name is not a host.
    assert Pnpm().parse({"pnpm-lock.yaml": PNPM_LOCK_REGISTRY_QUALIFIED}) == {
        "@scope/pkg": {"1.0.0"},
        "axios": {"1.6.0"},
        "foo": {"2.0.0"},
        "bar": {"3.0.0"},
        "lodash.merge": {"4.6.2", "4.6.3"},
        "@scope/aliased": {"5.0.0"},
    }
    # The managed Node.js runtime is not an npm package.
    assert "node" not in Pnpm().parse({"pnpm-lock.yaml": PNPM_LOCK_REGISTRY_QUALIFIED})


def test_pnpm_ignores_the_importers_and_snapshots_sections():
    # Only `packages:` lists resolved versions; `snapshots:` repeats them with peer suffixes.
    text = PNPM_LOCK_V9.replace("  qs@6.14.0:\n    resolution: {integrity: sha512-ccc}\n\n", "")
    assert "qs" not in Pnpm().parse({"pnpm-lock.yaml": text})


def test_pnpm_owns_its_lockfile_and_manifests():
    pnpm = Pnpm()
    assert pnpm.owns("pnpm-lock.yaml")
    assert pnpm.owns("apps/api/pnpm-lock.yaml")
    assert not pnpm.owns("package-lock.json")
    assert pnpm.allows("package.json")
    assert pnpm.allows("pnpm-workspace.yaml")
    assert not pnpm.allows("src/index.ts")
    assert [e.name for e in select("auto", ["pnpm-lock.yaml", "src/a.ts"])] == ["pnpm"]
    assert [e.name for e in select("pnpm,docker", [])] == ["pnpm", "docker"]


def test_pnpm_levels_are_semver():
    pnpm = Pnpm()
    assert pnpm.level({"1.18.1"}, {"1.18.2"}) == "patch"
    assert pnpm.level({"1.18.1"}, {"1.20.0"}) == "minor"
    assert pnpm.level({"11.2.7"}, {"12.0.0"}) == "major"


def test_pnpm_replay_is_manual(tmp_path):
    with pytest.raises(ReplayError, match="hotfix by hand"):
        Pnpm().replay(tmp_path, [("axios", "1.18.2")])
