<!-- start title -->

# GitHub Action: Renovate triage

<!-- end title -->

<!-- start description -->

Score the vulnerabilities fixed by a Renovate PR (CVSS) and route it (hotfix, automerge or review), with a Notion ticket for security fixes

<!-- end description -->

Part of the Renovate security flow: see [the guide](../renovate-security/README.md).

## Inputs

<!-- start inputs -->

| **Input** | **Description** | **Default** | **Required** |
| :-- | :-- | :-: | :-: |
| **`github_token`** | Token reading the GitHub Advisory Database and editing the PR (pull-requests and issues write) | `${{ github.token }}` | **false** |
| **`pr_number`** | Renovate PR to triage | `${{ github.event.pull_request.number }}` | **false** |
| **`base_sha`** | Base commit of the PR. Check it out (fetch-depth 0) before calling the action | `${{ github.event.pull_request.base.sha }}` | **false** |
| **`head_sha`** | Head commit of the PR, only read as git objects | `${{ github.event.pull_request.head.sha }}` | **false** |
| **`security_label`** | Whether Renovate labelled the PR `security` (a vulnerability fix without a known score is still reviewed as such) | `${{ contains(github.event.pull_request.labels.*.name, 'security') }}` | **false** |
| **`cvss_hotfix_threshold`** | CVSS from which a fix is shipped as a hotfix from the production commit. Above 10, no score reaches it and the hotfix flow is off | `9.0` | **false** |
| **`cvss_automerge_threshold`** | CVSS from which a fix is merged automatically when it only bumps patch versions | `4.0` | **false** |
| **`hotfix_enabled`** | Set to false to ship critical fixes through main (automerge tier, critical label, Notion P1) instead of a hotfix | `true` | **false** |
| **`ecosystems`** | auto, or a comma-separated list of uv, poetry, npm, pnpm, docker, upstream | `auto` | **false** |
| **`lockfile_dir`** | Only read dependency files under this directory (monorepos) |  | **false** |
| **`upstream_cpes`** | Multi-line `depName=vendor:product` NVD products for the `# renovate:` pins of Dockerfiles (e.g. `openssl/openssl=openssl:openssl`) |  | **false** |
| **`nvd_api_key`** | NVD API key, raises the NVD rate limit (upstream ecosystem) |  | **false** |
| **`notion_token`** | Notion integration token. Empty to skip the ticket |  | **false** |
| **`notion_data_source_id`** | Notion data source of the tickets | `01cee5a0-2b64-49a0-b9de-82198932bfb6` | **false** |
| **`notion_project`** | Prefix of the ticket Project option | `Technique` | **false** |
| **`notion_sub_tech_team`** | Prefix of the ticket Sub-Tech-Team option, empty to leave it unset |  | **false** |

<!-- end inputs -->

## Outputs

<!-- start outputs -->

| **Output** | **Description** |
| :-- | :-- |
| **`tier`** | hotfix, automerge, manual or none |
| **`max_cvss`** | Highest CVSS of the fixed advisories, empty when unknown |
| **`critical`** | true when the max CVSS is 9.0 or more |
| **`hotfix_pins`** | Space-separated `ecosystem:name==version` pins replaying the smallest fix (empty if it cannot be replayed) |
| **`pr_pins`** | Space-separated pins of the versions the PR locks |
| **`update_level`** | none, digest, patch, minor or major |
| **`ticket_id`** | Notion ticket id (ALG-NNNN), kept from the previous triage comment when Notion can't be reached |

<!-- end outputs -->

## Usage

<!-- start usage -->

```yaml
- uses: algoan/renovate-security-actions/renovate-triage@v1.0.0
```

<!-- end usage -->

A complete workflow: [`examples/renovate-triage.yml`](../renovate-security/examples/renovate-triage.yml).
