# Source register

SEC and cloud references reviewed October 10, 2026; local signing reference added October 11, 2026, America/Chicago. These official references informed the implementation and deployment plan. They establish service behavior, not proof that this particular installation has passed a test or is deployed.

| Source | What it informs | Project consequence |
| --- | --- | --- |
| [SEC EDGAR APIs](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) | Public JSON APIs, ten-digit CIK identifiers, recent submissions and separate older history files | Use the submissions endpoint without an API key. The collector's recent-filings scope is not a complete historical archive. |
| [SEC Accessing EDGAR Data](https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data) | Declared user agent; current maximum of 10 requests per second; corrections can occur | Supply a real operator contact, keep request volume low, preserve retrieved evidence, and report source failures. |
| [OpenSSH ssh-keygen](https://man.openbsd.org/ssh-keygen) | `-Y sign` and `-Y verify`, signing namespaces, allowed signer identities, and Ed25519 keys | Sign canonical local checkpoints with a project-specific namespace; verify against the pinned public identity. A signature requires a separately trusted key/reference, not merely a public key bundled with untrusted evidence. |
| [AWS S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) | Earlier object versions can support recovery; retained versions also incur storage charges | Enable versioning for cloud evidence. Versioning alone is not immutable storage and does not prevent authorized version deletion. |
| [AWS S3 CloudTrail logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html) | Object-level data events require explicit configuration and incur additional charges | Verify data-event coverage for the evidence bucket. Ordinary CloudTrail event history is not sufficient proof that reads and writes were captured. |
| [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html) | Cost notifications can lag incurred charges | Treat the budget as an alert, not a hard spending cap. Maintain a shutdown procedure and review actual costs. |
| [GitHub OIDC with AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws) | Short-lived workload authentication and restricted trust subjects | Avoid storing permanent AWS access keys in GitHub. Match the repository's actual OIDC subject and intended branch or environment. |

GitHub's current guide notes that repositories created after July 15, 2026, or opted into immutable subject claims use owner and repository IDs in the subject. Inspect the repository's actual configuration before enabling deployment; a copied subject example may not match. The guide is linked in the table above.

## Evidence boundaries

- SEC submissions metadata identifies filings. It does not establish that a company will beat market expectations or that its share price will rise.
- Filing date, SEC acceptance time, local retrieval time, and the reporting period are different fields. Keep their meanings separate.
- A saved source and matching hash establish a local consistency check against the stored reference. Signed checkpoints additionally compare sealed records against a public identity and latest checkpoint pinned outside the archive. That boundary detects archive-only replacement of both a filing and its database hash; it does not establish an independently trusted collection time, administrator-proof custody, or completeness.
- Protected restore requires an independently retained public receipt for the exact checkpoint. The receipt is a public trust reference, not the private signing key or a third-party timestamp. A receipt supplied only by the same potentially altered backup does not independently authenticate it.
- A live collection label means the collection used the live source path. It is not a claim of SEC endorsement, audited accuracy, or independent verification.
- Demo content is synthetic learning data and must remain visibly labeled. It must not enter a QES assessment as factual company evidence.
- This platform adds no QES gate, score, trade recommendation, or performance claim. Existing research and trading decisions stay separate.

## Refresh practice

Revisit these sources when changing collection frequency, authentication, storage retention, cloud logging, or deployment. Record the URL, review date, relevant change, and resulting implementation decision. Do not silently replace a historical research record because a source changes later.
