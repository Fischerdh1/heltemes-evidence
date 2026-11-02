# Reviewer edition verification — November 1, 2026

This is a new documentation/demo edition around application version 0.4.0. It does not change the runtime modules, install an update, deploy AWS, or replace the earlier release ZIP. The historical [installation verification](VERIFICATION.md) remains unchanged.

## Observed software results

On macOS with Python 3.14, the original reviewer edition passed **336 software tests** using:

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -v
```

Resource warnings were treated as errors. This total includes the new demo and packaging tests. Native account-installation tests in this suite use disposable fixtures/mocks; the count does not imply a new privileged account installation or a fresh run of the 19 historical actual-account checks.

Presentation revision R2 updates the project description, learning materials, and reviewer-page wording. Its eight packaging tests passed. Runtime modules, the demo's behavior, and the saved demonstration results are unchanged; the 336-test figure above describes the original full-suite run.

The final source demonstration completed at **2026-11-02T03:49:03Z UTC**, which is the evening of November 1 in America/Chicago. Its full timestamp and source hashes are retained in the bundle's `report/results.json`.

## Observed synthetic demonstration

All **12 phase outcomes** matched expectations. Three synthetic filings produced four evidence objects.

| Step | Observed result |
| --- | --- |
| Initial enrollment | Synthetic archive verified at checkpoint 1 under a new disposable identity |
| Alter document and mutable references | Byte/hash/size/path consistency and recomputed metadata fingerprints passed; signed verification rejected the changed accepted snapshot |
| Restore exact originals | Verification passed without changing the trusted checkpoint |
| Prepare approved practice key | Signing blocked under an explicitly labeled same-user authorization fixture |
| Crash before final completion publication | Worker exited with deliberate code 71; temporary completion existed and final completion was absent |
| Verify after crash | Public archive verified at checkpoint 2; fresh ordinary signing was refused because completion was missing |
| Explicit resume | Recovery revalidated and completed at checkpoint 2 |
| Fresh repeat resume | Returned `already_completed: true`; checkpoint, reference, and completion were unchanged |
| Ordinary signing | One new synthetic operational record was sealed at checkpoint 3; no new filing or identity transition was created |
| Final verification | Earlier checkpoints and completion remained unchanged; all four evidence objects verified |

The harness removed its temporary evidence and throwaway keys. Reports normalize local paths and retain no private key material. The demonstration does not consume a live archive, original signing key, saved live backup, or SEC contact setting.

## Packaging checks

The reviewer packager requires a passing, cleaned-up report; exact phase/check coverage; and demo/runtime hashes matching the source being included. Its tests cover changed source, failed checks, mismatched phase records, privacy exclusions, unsafe paths, and preservation of existing output files. The bundle contains source, the saved report, an offline HTML overview, metadata, and a SHA-256 inventory. It is a local reviewer artifact, not a new application release or public GitHub publication.

These checks establish consistency of the locally produced package. They do not make a self-contained report independent evidence of its own authenticity; a recipient should retain a trusted checksum and reproduce the demonstration.

## Limits

- No physical power-loss test, native recovery authorization exercise, hostile-administrator test, off-device backup verification, or AWS operation was performed for this edition.
- The portable demo uses same-user practice authority; the managed collector/custodian boundary is described and supported separately by historical native checks.
- No external security audit or new hosted CI run is claimed.
- The browser preview tool refused local-file navigation. The offline HTML report is generated from verified results; browser-rendered appearance was not visually checked in this session.

For the reproduction command and presentation script, see [REVIEWER_GUIDE.md](REVIEWER_GUIDE.md).
