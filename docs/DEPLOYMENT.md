# Deploying HELTEMES Evidence on AWS

This is the cloud component of **HELTEMES Evidence — Earnings Research Platform**. It preserves SEC source bytes and dated run manifests in S3. The local dashboard remains a separate, local application; it is not exposed to the internet by this stack.

**Current status:** deployment files and offline tests are provided. No AWS account has been connected, no resources have been created, and neither IAM enforcement nor a cloud collection has been verified against AWS. The implementation is a learning project, not a certified archive or an operated production service.

## What gets created

| Component | Purpose and boundary |
|---|---|
| Private, encrypted, versioned S3 evidence bucket | Raw content under `evidence/objects/sha256/`; each invocation has its own manifest under `evidence/runs/`. No automatic data expiry. |
| Lambda collector | Python 3.12, ARM64, 256 MiB, 180-second execution limit, one reserved concurrent execution. One company, 1–3 selected documents per run. |
| Collector role | Write new objects conditionally; create log streams and log events. No object read, list, delete, or IAM-management permission. |
| Reader policy | List the evidence prefix and read current or prior versions. Attach it to an existing restricted human/SSO role; the stack does not create user credentials. |
| EventBridge Scheduler | Once daily at 13:00 UTC by default, **disabled initially**. Scheduler and Lambda asynchronous retries are disabled to bound duplicate runs. |
| CloudWatch | 30-day logs, error and throttle alarms. A daily missing-invocation alarm is added when the schedule is enabled. |
| Optional notification email | SNS sends alarms after you confirm its subscription. Without an email, alarms appear only in AWS. |
| CloudTrail, enabled by default | Management events plus S3 data events scoped to the evidence prefix; separate private, versioned log bucket with integrity digest delivery enabled. |
| Optional AWS Budget | Account-wide actual-spend warning at 80% of the chosen amount; this does **not** stop charges. |
| Optional GitHub role | Can update this Lambda's code and inspect its update status. It cannot deploy Terraform or modify permissions. |

S3 `If-None-Match: *` prevents replacing an existing key, and the collector role is required to supply that condition. Repeated raw content reuses the same hash-derived key while each run gets a new manifest. A collision/precondition response does not download and verify the existing object: the archive reader must perform separate integrity checks. [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [policy enforcement](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html).

This protects against the collector accidentally overwriting evidence. Administrators can still change policies and versions. Versioning is not Object Lock, an independent backup, or proof that the contents existed before a trading decision.

## Before the first deployment

1. Choose a dedicated AWS learning account or clearly isolated sandbox. Enable MFA and use temporary credentials through IAM Identity Center/SSO. Never paste access keys into a chat, repository, `.tfvars` file, or GitHub secret for this workflow.
2. Install a supported Python (3.12+), AWS CLI v2, and Terraform (the project accepts 1.10–1.x; CI is pinned to 1.13.5).
3. Choose one region, one company CIK, and a real monitored contact email for SEC identification. Apple (`0000320193`) is the example configuration, not a trading recommendation.
4. Review the costs below. In an existing account, inspect existing CloudTrail trails before adding another management-event copy.
5. Use a provisioning identity permitted to manage this stack's S3, Lambda, IAM, Scheduler, Logs, Alarms, optional SNS/CloudTrail/Budgets resources. Your administrator must scope and review that access for the chosen account. This repository deliberately does not manufacture a broadly privileged deployer role.
6. Ensure the account's Lambda concurrency quota can reserve one execution while satisfying AWS's unreserved-capacity requirement. A restricted new-account quota may need adjustment before deployment.

## Local checks and the deployment plan

Run from the project directory. These first commands do not access AWS or SEC:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/package_lambda.py
```

The package uses a four-file allowlist: `heltemes/__init__.py`, `heltemes/sec.py`, `cloud/__init__.py`, and `cloud/handler.py`. It excludes local evidence, databases, contact configuration, Terraform state, test fixtures, and the dashboard. It uses the boto3/botocore supplied by the Lambda runtime; offline tests use fake clients. For fully pinned runtime dependencies in a future release, bundle and regularly update both libraries together.

Create your local configuration:

```sh
cp infra/terraform.tfvars.example infra/terraform.tfvars
```

Edit that file. Replace the SEC identity placeholder with your application name followed by your real email. Set `alert_email` to receive operational notices, and set `monthly_budget_usd` to your chosen account warning amount. Keep `enable_schedule = false`.

SEC contact information is stored in the Lambda environment and Terraform state. Marking a Terraform value sensitive masks normal console output; it does not encrypt the state file. Keep local state and saved plans on an encrypted disk, restrict their filesystem access, preserve a private backup, and exclude them from Git. For team work, migrate to a separately provisioned encrypted, versioned remote backend with restricted access and locking before another operator runs Terraform. [Terraform sensitive-data guidance](https://developer.hashicorp.com/terraform/language/manage-sensitive-data).

Authenticate to the selected AWS account locally, then inspect a plan:

```sh
aws sso login --profile heltemes-lab
export AWS_PROFILE=heltemes-lab
aws sts get-caller-identity
terraform -chdir=infra init
terraform -chdir=infra fmt
terraform -chdir=infra validate
terraform -chdir=infra plan -out=deployment.tfplan
```

`init` downloads providers. Review and commit the generated `.terraform.lock.hcl` after initialization; it is a dependency lock, not a secret. Keep `.terraform/`, `.tfstate*`, `.tfplan`, and your `.tfvars` private. Read the plan before any apply: confirm the account, region, disabled schedule, private storage, and optional resources. A successful validation is not evidence that permissions or collection work in AWS.

After the account owner approves that concrete plan and its costs, apply it:

```sh
terraform -chdir=infra apply deployment.tfplan
terraform -chdir=infra output
```

The agent has not run this apply. Do not label the project “deployed” based on the presence of these files.

## Verify the deployed system before scheduling it

Set shell variables from actual stack outputs, rather than guessing resource names:

```sh
COLLECTOR_NAME=$(terraform -chdir=infra output -raw lambda_function_name)
EVIDENCE_BUCKET=$(terraform -chdir=infra output -raw evidence_bucket)
AWS_REGION=$(terraform -chdir=infra output -raw region)
export AWS_REGION
mkdir -p work/cloud-verification
aws lambda invoke --function-name "$COLLECTOR_NAME" --cli-binary-format raw-in-base64-out --payload '{}' work/cloud-verification/invocation.json
cat work/cloud-verification/invocation.json
```

The invocation command's HTTP status does not establish application success. Check for `FunctionError` in its response, open the returned JSON, and require `status = complete`. Follow the exact `manifest_key` it returns. A complete result with `no_matching_filings = true` only means the request succeeded and no selected form appeared in the recent submissions; it does not establish comprehensive historical coverage.

For a successful result, download the manifest with your restricted reader profile:

```sh
MANIFEST_KEY=$(python3 -c 'import json; print(json.load(open("work/cloud-verification/invocation.json"))["manifest_key"])')
aws s3api get-object --profile heltemes-reader --bucket "$EVIDENCE_BUCKET" --key "$MANIFEST_KEY" work/cloud-verification/manifest.json
```

This example assumes you have configured `heltemes-reader` through your own SSO setup and attached the emitted reader policy. For a manifest containing a completed filing, verify its first document:

```sh
OBJECT_KEY=$(python3 -c 'import json; print(json.load(open("work/cloud-verification/manifest.json"))["filings"][0]["artifact"]["object_key"])')
aws s3api get-object --profile heltemes-reader --bucket "$EVIDENCE_BUCKET" --key "$OBJECT_KEY" work/cloud-verification/document.bin
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
folder = Path("work/cloud-verification")
manifest = json.loads((folder / "manifest.json").read_text())
expected = manifest["filings"][0]["artifact"]["sha256"]
actual = hashlib.sha256((folder / "document.bin").read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("FAIL: downloaded document differs from its manifest")
print("PASS: downloaded document matches its recorded SHA-256")
PY
```

Repeat for each artifact, including the submissions response. Record the accession, source URL, retrieved time, and hash result. These commands demonstrate content verification, not independent timestamp verification.

Complete these live acceptance checks and save dated evidence in `work/cloud-verification/`:

- **Identity and boundaries:** validate the expected AWS account, bucket, private-access settings, encryption, and versioning.
- **Reader restriction:** reading an existing artifact succeeds; attempting a harmless test-object write as that reader is denied. A policy attached alongside broader permissions is not a restricted reader—inspect its complete effective role.
- **Writer restriction:** use IAM policy simulation and a controlled Lambda test to confirm the collector cannot GetObject/DeleteObject and cannot PutObject without the condition. Do not grant humans permission to assume the collector role just to test it.
- **Preservation:** invoke again, compare manifests, and establish that unchanged bytes reuse a content key without replacing original objects.
- **Operational failure:** in a disposable test stack, simulate an unavailable source or temporary denied write; verify the Lambda Errors alarm changes state and the confirmed email receives it. Restore the intended configuration and verify recovery.
- **Object access audit:** retrieve a test object and inspect the delivered CloudTrail S3 data event in the audit log files. Default CloudTrail Event History alone does not establish object-level logging. Confirm trail delivery status and validate delivered log files with the CloudTrail tooling.
- **Recovery:** download an object by recorded version ID to a new location and re-hash it. Version recovery has not been proven until this succeeds.

CloudTrail data events require explicit selection; the stack selects only the evidence bucket prefix and excludes its separate log-delivery bucket. Check delivered events, rather than inferring coverage from the resource configuration. [AWS data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html), [CloudTrail bucket policy requirements](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).

The collector logs start and finish events. It records partial or failed manifests where possible, then raises an error so Lambda error monitoring sees the failure. In Lambda, SEC socket timeouts are five seconds with at most three attempts and two bounded Retry-After waits. Before starting a source request, the adapter requires 90 seconds for that request, 10 seconds for an artifact write, and 15 seconds reserved for the final manifest. If less time remains, selected documents are marked `deferred`, the run is `partial`, and Lambda raises an operational error. S3 uses one SDK attempt with a two-second connection and five-second read timeout to keep persistence bounded.

These reserves are defensive estimates, not hard end-to-end guarantees: a slow stream, hard timeout, process crash, or S3 outage may still prevent writing a finish manifest. Investigate a start with no finish and orphaned content objects. The Lambda timeout remains the final boundary. No automatic cleanup deletes those objects.

## Enable operation and pause safely

After live acceptance, edit `enable_schedule = true`, review a fresh plan, and apply it. Observe at least one scheduled invocation end to end. The provided missing-invocation alarm watches daily invocations; it is not a guarantee of successful collection and must be reviewed if you change the schedule. Errors/throttles and manifest status remain necessary signals. Manual runs also count toward that invocation metric.

To pause routine collection, return `enable_schedule` to `false`, review the plan, and apply. For an urgent incident, an authorized operator can set reserved concurrency to zero to stop new executions, then reconcile that emergency change in Terraform:

```sh
aws lambda put-function-concurrency --function-name "$COLLECTOR_NAME" --reserved-concurrent-executions 0
```

This does not cancel an invocation already running. Restore reserved concurrency to one only after investigation. Stored data, logs, trails, and alarms can continue to incur charges even when collection is paused. See [OPERATIONS.md](OPERATIONS.md) for the incident record and recovery workflow, and [THREAT_MODEL.md](THREAT_MODEL.md) for control limitations.

## Optional GitHub deployment

CI runs offline Python tests, packages the allowlisted source, and validates Terraform without AWS credentials. Commit hashes pin the actions; Dependabot proposes updates. Review and test each update instead of assuming a pin stays secure indefinitely.

The manual `deploy-code.yml` workflow updates code only; infrastructure remains managed by your locally reviewed Terraform plan. Before using it:

1. Publish the reviewed source to your intended repository and protect `main`.
2. Create a GitHub `production` environment, restrict its deployment branches to `main`, and configure an appropriate reviewer rule where available. The environment restriction is important because environment-based OIDC subjects do not encode the branch.
3. Have the account owner configure GitHub's OIDC provider in AWS with the `sts.amazonaws.com` audience. This project accepts an existing provider ARN; it does not create a general deployment identity.
4. Set `github_oidc_provider_arn` and **the exact verified** `github_oidc_subject` in the private Terraform inputs. Both must be supplied to enable the narrowly scoped code-update role.
5. Add environment variables `AWS_DEPLOY_ROLE_ARN` (from Terraform output), `AWS_REGION`, `AWS_ACCOUNT_ID`, and `LAMBDA_FUNCTION_NAME`. None are access keys. Run the workflow manually from `main`.

GitHub's official documentation says repositories created after July 15, 2026, or opted into immutable subjects, include owner/repository IDs, for example `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production`. Older repositories can use `repo:OWNER/REPO:environment:production`. Customized subjects can differ again. Verify your repository's actual subject; never use `repo:*` or guess the format. [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc), [AWS-specific GitHub guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

After code deployment, retain its commit and package hash, verify an invocation separately, and rebuild the same commit locally before a later Terraform apply. Otherwise the local Terraform package can roll the function back to different source. This workflow intentionally cannot change permissions, environment settings, or the collection schedule.

## Cost model and removal

At the default setting, one daily invocation selects up to two filings. Unchanged raw content is deduplicated, but a new run manifest, SEC retrievals, S3 conditional requests, log events, and audit events still occur. Storage grows over time; there is no “free forever” claim. No NAT gateway, always-on server, public API, or database service is created.

Before deployment, price these components for the chosen region and your account terms:

- Lambda requests and execution duration: [Lambda pricing](https://aws.amazon.com/lambda/pricing/).
- S3 stored bytes, requests, versions, retrieval and transfer: [S3 pricing](https://aws.amazon.com/s3/pricing/).
- CloudWatch ingestion, storage and alarms: [CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/).
- CloudTrail data events and any additional management copies: [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/).
- Scheduler, SNS and any budget feature charges: [Scheduler pricing](https://aws.amazon.com/eventbridge/pricing/), [SNS pricing](https://aws.amazon.com/sns/pricing/), [Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/).

The optional budget warning covers the entire account to include costs that do not inherit project tags. Budget data and notifications can be delayed; they are not a hard spending cap. [AWS budget guidance](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html).

For removal, first disable the schedule and preserve independently verified evidence, Terraform state, and audit records. Review a destroy plan and an explicit retention decision before removing anything. Both buckets use `force_destroy = false`; Terraform cannot silently empty their versions. Do not work around that protection with bulk deletion commands. A failed destroy can still remove other stack components, so it is not a harmless pause command. An owner can instead move retained buckets to a separate archive configuration and destroy only the reviewed operational resources. No automatic destroy workflow is provided.

## Evidence required before résumé claims

“Prepared Terraform infrastructure and tested an S3 collection adapter offline” is appropriate before deployment. “Deployed and operated an AWS research collector” requires a real deployment, observed scheduled runs, measured costs, tested access controls, and a demonstrated recovery. Record what you personally understand and have exercised; see the learning guide for transfer checks.
