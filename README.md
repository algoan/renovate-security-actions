# Renovate security actions

GitHub Actions that route [Renovate](https://docs.renovatebot.com/) PRs according to the vulnerabilities they fix, for Algoan's **public** repositories.

| Action | Role |
|---|---|
| [`renovate-triage`](renovate-triage/) | Scores the CVEs fixed by a Renovate PR (max CVSS), creates the Notion ticket, labels the PR, comments the advisories and the ticket |
| [`renovate-auto-approve`](renovate-auto-approve/) | Approves Renovate's own commits, so a Renovate PR needs one human review |
| [`renovate-automerge`](renovate-automerge/) | Merges green automerge-tier PRs that only bump patch versions or digests |

The guide, the routing and the security model: [`renovate-security/README.md`](renovate-security/README.md).

```yaml
- uses: algoan/renovate-security-actions/renovate-triage@<commit SHA> # v1.0.0
```

A public repository can't call the actions of a private one, so these actions live here instead of a private repository, and need no token to be fetched.
