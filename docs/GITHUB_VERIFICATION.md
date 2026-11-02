# GitHub-hosted verification

Repository: [Fischerdh1/heltemes-evidence](https://github.com/Fischerdh1/heltemes-evidence). Dates below use America/Chicago.

## Original source verification — November 1, 2026

The repository began private with a reviewed 97-file source snapshot. Before upload, all 336 software tests passed locally on macOS/Python 3.14. GitHub then ran the same 336 tests successfully on Ubuntu with Python 3.12 and Python 3.14, built the collector package, and passed Terraform formatting, initialization with `-backend=false`, and configuration validation. These are 336 distinct tests exercised on two interpreters, not 672 distinct tests.

The upload excluded actual filings, databases, signing keys, contact settings, private trust records, backups, environment secrets, and Terraform state. The original local Git history remains local. Historical run logs and the original import identifiers are retained in the local verification record.

## Commit-email privacy correction

The initial source-file review missed a personal email address in Git commit metadata. The correction uses the account's GitHub-provided private commit address. Changing author or committer metadata also changes Git commit identifiers and descendant identifiers; it does not change the application's signed evidence checkpoints.

The completed metadata rewrite preserved every source tree, file, executable bit, commit message, author/committer name, and timestamp. Invalidated Git commit signatures were removed. This correction did not access or change the real evidence archive, its signing key, or its trusted history. Rewriting visible branch history does not erase old copies, cached views, or GitHub pull-request references.

The original test results above remain historical observations. Fresh verification of the rewritten history is recorded separately below; identical source trees alone were not treated as a new hosted test run.

## Verification after the correction

- Verified source commit: [`8c4a3f3e258021a81c31c13a01ea1e7aad51d112`](https://github.com/Fischerdh1/heltemes-evidence/commit/8c4a3f3e258021a81c31c13a01ea1e7aad51d112)
- GitHub run: [Verify project](https://github.com/Fischerdh1/heltemes-evidence/actions/runs/41394424346)
- Observation date: November 1, 2026

| Job | Result | Observed checks |
| --- | --- | --- |
| Python 3.12 on Ubuntu | Success | 336 tests passed; collector package built |
| Python 3.14 on Ubuntu | Success | 336 tests passed; collector package built |
| Terraform on Ubuntu | Success | Formatting, backend-disabled initialization, and configuration validation passed |

The README badge reports the current `main` workflow status and can change after later commits. The dated record above applies only to its identified commit and run.

## Branch safeguards

[Protect main — verified changes](https://github.com/Fischerdh1/heltemes-evidence/rules/26343619) was confirmed active on November 1, 2026. It applies to `refs/heads/main`, requires a pull request and resolved review conversations, and requires the `python (3.12)`, `python (3.14)`, and `terraform` checks from GitHub Actions against up-to-date code. Force pushes and branch deletion are blocked. The bypass list is empty.

The required human approval count is zero because this is a solo-maintained project; this is not a claim of independent human review. The repository administrator can still edit the ruleset. These GitHub controls are separate from local evidence custody.

## Boundaries

- The suite includes the disposable reviewer demonstration and expected tamper, rejection, and crash/restart outcomes. Hosted software checks do not repeat the historical native macOS collector/custodian permission checks; privileged macOS behavior uses disposable fixtures and mocks here.
- Terraform validation and building a Lambda ZIP do not deploy AWS. AWS remains undeployed; no infrastructure apply, cloud schedule, or cloud credential configuration is part of this work.
- The local signing key, real archive, and trusted history were not supplied to GitHub.
- Dependency-update proposals remain separate changes. Passing checks do not constitute approval or automatic merging of those proposals.

See the [reviewer guide](REVIEWER_GUIDE.md) for the demonstration and [historical local verification](VERIFICATION.md) for the managed installation's separate evidence.
