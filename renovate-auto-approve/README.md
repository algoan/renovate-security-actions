<!-- start title -->

# GitHub Action: Renovate auto-approve

<!-- end title -->

<!-- start description -->

Approve the commit Renovate pushed, so that a Renovate PR needs a single human review

<!-- end description -->

Part of the Renovate security flow: see [the guide](../renovate-security/README.md).

## Inputs

<!-- start inputs -->

| **Input** | **Description** | **Default** | **Required** |
| :-- | :-- | :-: | :-: |
| **`github_token`** | Token approving the PR (pull-requests write; enable "Allow GitHub Actions to create and approve pull requests") | `${{ github.token }}` | **false** |
| **`renovate_app_slug`** | Slug of the GitHub App Renovate runs as (`renovate` for the Mend app, your own app when Renovate is self-hosted) | `renovate` | **false** |

<!-- end inputs -->

## Outputs

<!-- start outputs -->

| **Output** | **Description** |
| :-- | :-- |
| **`approved`** | true when the head commit was approved |

<!-- end outputs -->

## Usage

<!-- start usage -->

```yaml
- uses: algoan/renovate-security-actions/renovate-auto-approve@v1.0.0
```

<!-- end usage -->

A complete workflow: [`examples/renovate-auto-approve.yml`](../renovate-security/examples/renovate-auto-approve.yml).
