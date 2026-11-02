# First real SEC filing — guided walkthrough

**HELTEMES Evidence — Earnings Research Platform**

Collected October 10, 2026, America/Chicago. The steps were operated by the assistant at Fischer's request; they do not claim Fischer independently performed or mastered them.

## What we obtained

| Field | Observed value |
|---|---|
| Company | Apple Inc. |
| CIK (company identifier) | 0000320193 |
| Form | 10-Q, a quarterly report |
| Accession (filing identifier) | 0000320193-26-000020 |
| Reporting period ended | June 27, 2026 |
| Filing date | July 31, 2026 |
| SEC acceptance time | 2026-07-31T14:01:02.000Z |
| First local retrieval | 2026-10-11T03:42:33Z; October 10 at 10:42:33 p.m. Central |
| Primary document | aapl-20260627.htm; 1,018,321 bytes |
| First successful run | f5d142eb9eaa4c238085673c3648fbe1 |

[Original document on SEC.gov](https://www.sec.gov/Archives/edgar/data/320193/000032019326000020/aapl-20260627.htm)

This was the first matching 10-Q in the recent-submissions response obtained by the collector. It does not establish full historical coverage or constitute an Apple trade review.

## 1. Identify the collector

We saved the supplied email in `data/settings.json` with owner-only permissions. The collector includes a project name and contact email in its HTTP `User-Agent` header. This identifies the operator to the SEC; it is neither a password nor an API key. Settings stay outside Git, source packages, and evidence backups. At the time of these first collections, the configured identification name was HELTEMES Research. The subsequent product rename does not change those historical collection facts.

[SEC access guidance](https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data) explains automated access identification and fair-access limits. This collector limits itself to one request per second within a process.

## 2. Request the company filing list

The input was CIK `0000320193`, form `10-Q`, limit `1`. The CIK identifies the company. The form filters the document type. The limit bounds how many matching documents we request.

The collector requested the SEC's submissions JSON: a machine-readable list of filings. It checked the company identifier and aligned filing fields before selecting the first match. Public SEC APIs need no API key. [SEC API documentation](https://www.sec.gov/search-filings/edgar-application-programming-interfaces)

## 3. Resolve a real security failure

The first attempt failed because this Python installation could not locate its default trusted certificate bundle. TLS is the protection that verifies the HTTPS endpoint and encrypts the connection. We retained the failed attempt, diagnosed the missing trust roots, and used the installed macOS CA bundle. We did not turn off certificate verification.

The collector now uses that system bundle when macOS Python has neither default certificate path. Explicit certificate settings are honored, and invalid overrides fail closed. New processes use this fix. The preview process that was already running must be restarted before its collection button uses the changed code; a browser refresh alone does not reload Python.

## 4. Preserve the source and the document

The output includes the original submissions JSON, the primary filing bytes, a searchable database entry, and collection observations. Saving both source and interpretation lets us revisit where the indexed fields came from.

We inspected the document's embedded identity fields and confirmed Apple Inc., the CIK, form 10-Q, and period end all match the selected metadata. The file was a filing, not merely an error page returned with a successful HTTP status.

## 5. Check fingerprints

SHA-256 converts file bytes into a fixed-length fingerprint. The integrity check recomputes each fingerprint and compares it with the saved record. All six objects passed: four sample objects plus the real submissions response and document.

Document SHA-256:

```text
19482308e52c154b75b31a3f3c5f34ff2a8d45bbb118f56c91849266193232c0
```

Submissions JSON SHA-256:

```text
2821703cf04e1138923243a87cc5148673feb9d3792a5b6a7747d1e1a093bf7f
```

A matching hash supports local consistency. It does not prove the truth of the issuer's statements, prevent an administrator from rewriting both files and hashes, or prove we possessed the document before tonight.

## 6. Repeat without inflating the archive

A second collection finished at `2026-10-11T03:44:54Z` using the normal configured collector without a certificate override. It found the same filing and added zero duplicate filing records. A second observation records that we checked again. This is the difference between a filing and an attempt to collect it.

## 7. Test recovery

We backed up the database and all six evidence objects, restored into a separate test directory, and verified the restored copy. The original remains intact. The archive is `HELTEMES-first-live-evidence-2026-10-10.zip` in the parent outputs folder; it excludes the email settings. This same-computer backup is a tested recovery artifact, not protection against losing the computer.

## 8. Explain it yourself

Open the dashboard, find Apple, and select **Inspect**. Point to the accession, filing date, first retrieval time, source URL, and document fingerprint. Then explain the data flow aloud:

**Input:** company identifier and requested form → **Processing:** verified HTTPS request, validation, selection, and hashing → **Output:** preserved evidence and a searchable record.

Try this transfer check: if a filing was public in July but downloaded in October, which date establishes when this system first collected it? Why would using July as the local collection date distort a historical trading study?

**Verbal checkpoint — October 10, 2026, America/Chicago:** Fischer correctly distinguished the filing's original date from this system's later retrieval date. This demonstrates the timestamp distinction in one verbal check. It does not establish independent operation, recovery, TLS troubleshooting, or completion of the full lesson or learning path. The next step is to locate both timestamps in the saved record and explain a new example without prompting.

## Adopted product name

On October 10, 2026, Fischer adopted **HELTEMES Evidence**, with **Earnings Research Platform** as the subtitle. This records the chosen product name; no domain check or trademark clearance is claimed.

Its resume value will come from demonstrated operation and understanding: explaining this TLS failure, showing evidence history, recovering the archive, and independently making tested changes. The name alone will not distinguish the project.
