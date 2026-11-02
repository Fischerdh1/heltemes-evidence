# GitHub-hosted verification

First observed November 1, 2026, America/Chicago (November 2 UTC). Repository: [Fischerdh1/heltemes-evidence](https://github.com/Fischerdh1/heltemes-evidence).

## First source import

The repository began private with a reviewed source-only snapshot. The 97-file import excluded actual filings, databases, signing keys, contact settings, private trust records, backup archives, environment secrets, and Terraform state. The prior local Git history remains local; this is a new GitHub history for the portfolio snapshot.

- Source import commit: [`9da1209d042b5a4c4878577d4d41c1dfde08cb82`](https://github.com/Fischerdh1/heltemes-evidence/commit/9da1209d042b5a4c4878577d4d41c1dfde08cb82).
- Verification run: [Verify project #1](https://github.com/Fischerdh1/heltemes-evidence/actions/runs/41388588508).
- Local export preflight: 336 tests passed on macOS/Python 3.14 before upload.

## Observed hosted results

| Job | Result | Observed checks |
| --- | --- | --- |
| Python 3.12 on Ubuntu | Success | All 336 software tests passed; collector package built |
| Python 3.14 on Ubuntu | Success | The same 336 software tests passed; collector package built |
| Terraform on Ubuntu | Success | Formatting passed; initialization with `-backend=false` succeeded; configuration validation succeeded |

The two Python jobs execute the same suite on different interpreters; these are not 672 distinct tests. The suite includes the synthetic reviewer demonstration and expected rejection/crash cases. Passing means each expected outcome was observed.

The record above refers to the exact source-import commit. The README badge links to the current `main` workflow status, which can change after later commits. Preserve this dated record rather than rewriting it as a result for a newer commit.

## Boundaries

- Hosted software tests do not repeat the historical native macOS collector/custodian permission checks. Privileged macOS behavior uses disposable fixtures and mocks in this suite.
- Terraform validation and creating a Lambda ZIP do not deploy AWS. No infrastructure apply, cloud schedule, or credential configuration was performed.
- The local signing key, real archive, and trusted history were not supplied to GitHub.
- Dependency-update proposals are separate changes. A passing source-import run does not approve or merge later proposals.

See the [reviewer guide](REVIEWER_GUIDE.md) for the demonstration and [historical local verification](VERIFICATION.md) for the managed installation's separate evidence.
