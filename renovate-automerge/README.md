<!-- start title -->

# GitHub Action: Renovate automerge

<!-- end title -->

<!-- start description -->

Merge a green Renovate security PR in the automerge tier that only bumps patch versions (or digests), or the Renovate PR of a promoted hotfix

<!-- end description -->

Part of the Renovate security flow: see [the guide](../renovate-security/README.md).

## Inputs

<!-- start inputs -->

| **Input** | **Description** | **Default** | **Required** |
| :-- | :-- | :-: | :-: |
| **`github_token`** | Token reading the PR, its checks and the advisories. Without app_id, it also merges the PR (contents and pull-requests write) | `${{ github.token }}` | **false** |
| **`app_id`** | ID of the GitHub App merging the PR (a pull-request bypass actor of the base branch ruleset). Empty to merge with github_token, where the branch ruleset requires no approval |  | **false** |
| **`private_key`** | Private key of that GitHub App. Empty with app_id |  | **false** |
| **`pr_number`** | PR to merge. Defaults to the open PR of the workflow_run head branch |  | **false** |
| **`renovate_app_slug`** | Slug of the GitHub App Renovate runs as (`renovate` for the Mend app, your own app when Renovate is self-hosted) | `renovate` | **false** |
| **`renovate_email`** | Commit author email of that app's bot (`<bot user id>+<slug>[bot]@users.noreply.github.com`, the id from `gh api 'users/<slug>[bot]'`) | `29139614+renovate[bot]@users.noreply.github.com` | **false** |
| **`hotfix_app_slug`** | Slug of the GitHub App opening hotfix PRs (renovate-open-hotfix) | `algoan-merger` | **false** |
| **`required_checks`** | Comma-separated check names (the CI jobs) that must have succeeded on the head commit. Required, so a PR is never merged before its CI has started |  | **true** |
| **`allowed_paths`** | Extra space-separated path globs the PR may change (e.g. `k8s/ray-service-*.yaml`). Dependency files of the selected `ecosystems` and files with `<!-- renovate:` markers are always allowed under lockfile_dir |  | **false** |
| **`merge_method`** | How the PR is merged, `squash`, `merge` or `rebase`; the repository must allow it (e.g. `merge` where squash is off and the release reads every conventional commit) | `squash` | **false** |
| **`cvss_hotfix_threshold`** | Same value as renovate-triage | `9.0` | **false** |
| **`cvss_automerge_threshold`** | Same value as renovate-triage | `4.0` | **false** |
| **`hotfix_enabled`** | Same value as renovate-triage | `true` | **false** |
| **`ecosystems`** | Same value as renovate-triage | `auto` | **false** |
| **`lockfile_dir`** | Same value as renovate-triage; dependency files outside it need allowed_paths |  | **false** |
| **`upstream_cpes`** | Same value as renovate-triage |  | **false** |
| **`nvd_api_key`** | Same value as renovate-triage |  | **false** |

<!-- end inputs -->

## Outputs

<!-- start outputs -->

| **Output** | **Description** |
| :-- | :-- |
| **`merged`** | true when the PR was merged |

<!-- end outputs -->

## Usage

<!-- start usage -->

```yaml
- uses: algoan/renovate-security-actions/renovate-automerge@v1.0.0
  with:
    required_checks: ""
```

<!-- end usage -->

A complete workflow: [`examples/renovate-automerge.yml`](../renovate-security/examples/renovate-automerge.yml).
