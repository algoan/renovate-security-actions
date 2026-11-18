from __future__ import annotations

from .base import Ecosystem, ReplayError, Versions
from .docker import Docker
from .npm import Npm
from .pnpm import Pnpm
from .python import Poetry, Uv
from .upstream import Upstream

ECOSYSTEMS = {cls.name: cls for cls in (Uv, Poetry, Npm, Pnpm, Docker, Upstream)}


def select(names: str, paths: list[str]) -> list[Ecosystem]:
    """Ecosystems listed in `names` (comma-separated), or every one owning a file in `paths`."""
    if names.strip() in ("", "auto"):
        return [cls() for cls in ECOSYSTEMS.values() if any(cls().owns(p) for p in paths)]
    unknown = [n.strip() for n in names.split(",") if n.strip() not in ECOSYSTEMS]
    if unknown:
        raise ValueError(f"Unknown ecosystems: {', '.join(unknown)} (known: {', '.join(ECOSYSTEMS)})")
    return [ECOSYSTEMS[n.strip()]() for n in names.split(",") if n.strip()]


__all__ = ["ECOSYSTEMS", "Ecosystem", "ReplayError", "Versions", "select"]
