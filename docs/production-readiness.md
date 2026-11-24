# Production deployment readiness package

Raw scan evidence, generated manifests and image archives are intentionally excluded from Git. References to `reports/` identify local review evidence, not committed files. CI produces fresh validation artifacts; retrieve local evidence through an authorized channel when required.

Review date: 2026-11-24, America/Chicago. **Decision: NO GO for production traffic.**
This package assigns work to responsible roles; it does not assign named owners or
grant approvals. Nothing in this review deploys, pushes, provisions, rotates a real
credential, or accepts an exception. All target account, cluster, DNS and identity
values remain unverified.

Latest image evidence: [SQLite/OpenSSL dispositions](sqlite-openssl-dispositions.md)
and rebuilt-image manifest (local-only evidence: `reports/cve-review-manifest.json`). Alpine 3.24 policy
and package history were checked, an uncached rebuild was tested/scanned, and no
compatible fixed package was available for the five CVEs. The review is complete;
remediation or authorized applicability dispositions remain open. **NO GO**.

Two approvals are distinct: authorization for a controlled deployment to collect
live evidence, and authorization to open production traffic. Post-deployment
checks cannot be marked passed before that controlled deployment. Every item below
needs an evidence reference, reviewer, timestamp, target environment and exact
source/image identity. A passing command is evidence for its stated scope only.

## Package contents and current evidence

- [Deployment and rotation runbook](../README.md#production-deployment-procedure-not-executed).
- [Read-only release input check](../scripts/check_release_inputs.py): blocks unresolved
  markers and images without a digest; it does not verify provenance or approval.
- [Secret synchronization helper](../scripts/sync_api_secret.py): an operator-only
  action. It has not been run against AWS or Kubernetes.
- Final configuration scan (local-only evidence: `reports/production-config-final.json`): two S3 findings
  remain; namespace/registry findings are resolved by the proposed static policy.
- Dependency audit (local-only evidence: `reports/production-dependencies.json`): 53 packages, no known
  vulnerabilities at the previous review; source dependencies are unchanged.
- Historical inspection (local-only evidence: `reports/readiness-fixture-review.json`): exact flagged
  lines checked in memory; no literal values or their hashes were emitted.
- [Image investigation](image-vulnerability-review.md), complete occurrence groups (local-only evidence: `reports/image-vulnerability-groups.md`)
  and latest candidate scan (local-only evidence: `reports/cve-image-scan.json`): the previous 222
  occurrences are reproduced, grouped and investigated. Five manual HIGH reviews
  remain despite zero matches in the Alpine feed. Source auditing alone is insufficient.
- Candidate SBOM (local-only evidence: `reports/cve-image-sbom.cdx.json`) and
  evidence manifest (local-only evidence: `reports/readiness-image-summary.json`): package inventory,
  local image identity, source-file hashes and explicit unapproved status.
- CloudFront regression report (local-only evidence: `reports/cloudfront-check.json`): `AWS-0010`
  correctly fails the unlogged fixture and passes the logged fixture. No actual
  CloudFront distribution exists in the project's Terraform.

Local evidence: 77 tests passed; 66 API/scanner tests also passed inside the smaller
image with no network, read-only root filesystem and no published ports. Local tests
reported two upstream warnings; image tests reported those plus two pytest rewrite
warnings. Actual server startup/health/log-redaction smoke checks passed. Ruff passed. Terraform
1.17.2 previously validated the unchanged Terraform configuration using AWS provider
5.100.0; no plan or account access was performed. A new image build succeeded.

The current Dockerfile pins an official Python 3.12 Alpine 3.24 base, applies available
OS updates, and separates runtime from build/test dependencies. Local virtualenv
development is unchanged. Historical scans reported 258 occurrences before Debian
updates and 222 afterward. The latter rescan confirms **53 HIGH, 74 MEDIUM, 79 LOW,
16 UNKNOWN**, representing 99 unique IDs (87 CVEs), with no reported fixed versions.
The new Alpine scan reports **zero occurrences**, but advisory/package inspection
leaves **five manual HIGH CVE reviews open** in SQLite and OpenSSL. Do not interpret
the change of distribution feed as proof that those vulnerabilities were fixed.
See the investigation for all 13 baseline HIGH CVEs, runtime evidence and next actions.
The Alpine/musl platform change also requires target-environment compatibility validation.
The image identity and hashes are recorded in `reports/readiness-image-summary.json`.
A local image ID is not an approved registry
digest, and no image has been pushed by this review.

## Work that can be completed and tested locally

| ID | Action and reason | Exact file or resource | Responsible role | Validation | Evidence needed to close |
|---|---|---|---|---|---|
| L1 | Build, scan and triage the complete image. Uncached candidate rebuilt/tested; five manual HIGH dispositions remain open despite zero feed matches. | `Dockerfile`, `requirements*.txt`, candidate `ai-devsecops-readiness:cve-review`; `docs/sqlite-openssl-dispositions.md` | Release engineer with security owner | Exact commands in `reports/cve-review-commands.md`; scan without `--ignore-unfixed`. | Build, inventory, layer identity, SBOM, full scan and verified fix/applicability evidence for each manual item. No release approval yet. |
| L2 | Check API behavior, privacy and operator helper errors. Reconfirm after any release change. | `src/app/`, `scripts/`, `tests/`, `config/logging.json` | Application maintainer | `python -m pytest -q -p no:cacheprovider`; `python -m ruff check src scripts tests`; `python -m bandit -r src scripts -f json -o reports/readiness-bandit.json` | Test/lint results tied to the release snapshot; Bandit review X3, not a claim of zero findings. Current tests/lint passed. |
| L3 | Fail closed on unresolved image, hostname, gateway and peer selectors. A syntactically valid placeholder is not deployable. | `scripts/check_release_inputs.py`; `k8s/*.yaml` | Platform engineer | `python scripts/check_release_inputs.py` | Exit 0 on final rendered inputs, plus E1–E4 approvals. Currently expected to exit 1 because environment values are missing. |
| L4 | Validate Terraform and provider selection without cloud mutation. Preserve resource names/state when migrating. | `terraform/main.tf`, `terraform/.terraform.lock.hcl` | Cloud administrator | `terraform -chdir=terraform init -backend=false -input=false`; `terraform -chdir=terraform fmt -check`; `terraform -chdir=terraform validate` | Valid configuration and provider lock; an authenticated reviewed plan is a separate E5 step. Local schema validation passed. |
| L5 | Inspect historical fixture findings without displaying values; investigate possible reuse. | `examples/insecure/bad-main.tf:21`, commits listed under X4 | Repository maintainer and security owner | `python reports/readiness-inspect-fixtures.py`; inspect only the resulting metadata JSON. | The assignment and equality checks passed. Signed origin/use-history evidence under X4 is still required; equality does not prove a value was never real. |

### Local build and scan commands

Run from the repository root in a shell appropriate to the host. These commands
build and scan locally; they do not push. The scan container mount paths must be
adapted to the host. Local image archives are gitignored and contain application
code; store/restrict them as release artifacts, not public attachments.

```bash
# A1
docker build --pull -t ai-devsecops-readiness:alpine .
docker image inspect ai-devsecops-readiness:alpine --format '{{.Id}}'
docker image save --output reports/image-alpine.tar ai-devsecops-readiness:alpine

# A2, with Trivy 0.76.2 installed, or the equivalent pinned scanner container
trivy image --input reports/image-alpine.tar --scanners vuln,secret --list-all-pkgs \
  --format json --output reports/image-alpine-scan.json
trivy convert --format cyclonedx --output reports/image-alpine-sbom.cdx.json reports/image-alpine-scan.json

# A3, source/configuration checks are distinct from the image scan
trivy fs --config trivy.yaml --format json --output reports/readiness-source.json .
python -m pip_audit -r requirements.txt -r requirements-dev.txt
```

The existing Trivy CI step is report-producing and does not itself authorize a
release. The release owner must choose severity/exploitability policy and enforce
it in the release process; default scan exit 0 must not be interpreted as no
findings. Do not silently add ignores for the two pending S3 exceptions.

## Configuration requiring target values or decisions

Commands in this section are **future validation instructions**, not actions run
by this review. Bash variables below must be populated by an authorized operator
from the target inventory. No real values are supplied here. Do not put credentials
in variables used as command-line arguments, shell tracing or evidence documents.

| ID | Action and reason | Exact file or resource | Responsible role | Validation command or step | Evidence needed to close |
|---|---|---|---|---|---|
| E1 | Select approved repository, release platform, build provenance and immutable digest. Do not substitute a local image ID for the registry manifest digest. Adopt the proposed owner policy or change it through review. | `k8s/deployment.yaml` container `api`; `security/trivy-data/registry.yaml`; owner-prefix assertion in `tests/test_production_controls.py` | Release engineer and security owner | After a separately authorized publication, `docker buildx imagetools inspect "$RELEASE_IMAGE"`; verify its signature with the organization's approved identity/key and compare scan/SBOM to the selected platform digest. Then run L3. | Approved `ghcr.io/pfoseh-ops/ai-devsecops-platform@sha256:…`, signature/provenance, scan, SBOM and approval record. Registry publication was not performed here. |
| E2 | Provision a high-entropy raw single-line API key in AWS Secrets Manager. Select account, region, ARN, key policy, operator permissions and rotation owner. Kubernetes receives a copy; this is not automatic synchronization. | Secret ARN TBD; `scripts/sync_api_secret.py`; Kubernetes `ai-devsecops/ai-devsecops-api`, key `api-key`; `k8s/deployment.yaml` | Cloud administrator and platform engineer | `aws secretsmanager describe-secret --secret-id "$SECRET_ARN" --query '{ARN:ARN,KmsKeyId:KmsKeyId,Stages:VersionIdsToStages}'`. Review IAM access to this ARN and its KMS key. Do not use `get-secret-value` in the terminal. | Metadata-only secret inventory, policy review, approved trusted CLI binaries/host, encryption/audit design, future sync/rotation evidence P4. Never attach secret data. |
| E3 | Select real DNS name, gateway/controller, certificate authority/renewal owner, TLS policy, exact public route, timeout/body-limit values, internal HTTP versus platform mTLS. Certificate Secret must be managed, not committed. | `k8s/ingress.yaml` `ai-devsecops-api`, TLS Secret `ai-devsecops-tls`; existing gateway configuration outside this repo | Network/platform engineer and security owner | `dig +short "$API_HOST"`; `kubectl --context "$CTX" get ingressclass "$INGRESS_CLASS" -o yaml`; inspect rendered gateway config offline for TLS 1.2/1.3, 308 redirect, HSTS, limits, auth and redaction. | DNS/certificate inventory, issuer/renewal alert plan, approved controller config and hostname, ingress render, P1 test plan. Current template values are unresolved. |
| E4 | Confirm NetworkPolicy-capable CNI, actual gateway namespace/pod labels, restricted admission and signed-image/digest policy. Protect namespace labels and admission policies from workload users. | `k8s/namespace.yaml`; `k8s/network-policy.yaml` `api-gateway-only`; `k8s/deployment.yaml`; cluster admission configuration | Platform engineer | `kubectl --context "$CTX" get ns ai-devsecops --show-labels`; inspect CNI configuration and gateway labels. In the target environment, perform server-side dry-run admission tests for safe and forbidden images/pod settings. | CNI capability/version evidence, exact rendered AND selectors, namespace RBAC, admission policy review, positive and negative test results P2. A YAML declaration alone is not enforcement. |
| E5 | Supply bucket names, region/account, state backend, KMS administrators/users, retention, migration and recovery choices. Review ACL compatibility and existing-object encryption. | `terraform/main.tf`: `artifact_bucket_name`, `access_log_bucket_name`, `aws_region`, `log_retention_days`, `aws_kms_key.artifacts` and S3 resources | Cloud administrator, data owner and security owner | In an authorized environment, `aws sts get-caller-identity`; use an encrypted remote backend, then review an authenticated Terraform plan using protected tfvars. Verify imports/state addresses and reject unexpected replacement. Plan creation is not authorized/executed by this package. | Account/region attestation, protected plan/state access, no destructive replacements, approved retention/cost/backup policy, key grants, migration plan and X1/X2 disposition. Proposed 365-day retention is not approved. |
| E6 | Define identities, role/scope mapping, allowed clients, service-to-service key custody and shared distributed quota. Reuse the existing gateway/IdP and managed limiter; add infrastructure only for a demonstrated gap. | Gateway/IdP outside repo; `src/app/main.py` authorization; `src/app/security.py` per-process deque | Identity/security owner and platform engineer | Review issuer, audience, signature algorithms, expiry, `devsecops:analyze` scope, role mapping, header stripping/overwrite and bypass protection. Specify quota/window/burst/concurrency and run P3. | Approved permission matrix and quotas; gateway configuration showing distributed state; denial/expiry/replica tests. No such infrastructure was configured here. |
| E7 | Choose audit destinations, retention, access and telemetry allowlists. Redact at the emitter, not only after ingestion. Kubernetes Secret audit events must not record bodies. | `config/logging.json`, `Dockerfile`; proxy/WAF/APM/collector configs; Kubernetes audit policy | Observability engineer and security owner | Review formats for raw request lines, queries, headers, bodies, exception locals and WAF samples; configure Secret audit level Metadata. Run P6 with synthetic data. | Approved field allowlist, configuration versions, access controls, retention and all-system search evidence. Application unit tests do not cover external systems. |

## Checks requiring a deployed target

These checks need a separately authorized controlled deployment or an existing
staging target. Diagnostic pods, S3 test uploads and key rotation are changes, even
when called tests: obtain authorization for them. No command here was executed
against a cluster, AWS account, gateway, DNS zone or logging service during this work.

| ID | Action and reason | Exact resource | Responsible role | Concrete verification | Evidence needed to close |
|---|---|---|---|---|---|
| P1 | Verify actual TLS, host routing, renewal and proxy trust. | Selected hostname; Ingress `ai-devsecops/ai-devsecops-api`; gateway; TLS Secret | Network/platform engineer | `curl -sS -o /dev/null -D - "http://$API_HOST/analyze"` must redirect to the exact HTTPS host without exposing credentials. `openssl s_client -connect "$API_HOST:443" -servername "$API_HOST" -verify_return_error </dev/null` must validate the chain. Verify expiry/SAN, TLS 1.0/1.1 rejection, HSTS, wrong-host rejection and docs not publicly routed. Send synthetic spoofed forwarding/identity headers and confirm they confer no access. | Redacted protocol results, certificate metadata, renewal/expiry alert test and gateway config hash. App currently uses `--no-proxy-headers`; do not enable wildcard trusted proxies. |
| P2 | Verify network and admission enforcement, not just object existence. | `api-gateway-only`; gateway pods; unrelated pod; image admission and restricted namespace | Platform engineer | From an authorized gateway diagnostic context, connect to `ai-devsecops-demo.ai-devsecops.svc:80/health`; from an authorized unrelated test pod the same connection must time out/be denied. Confirm API egress is denied and node health probes work. Server-side dry-run a privileged pod, an unapproved registry and a mutable image; each must be denied by the appropriate admission policy. | Positive/negative results with source pod/namespace identities, CNI flow evidence, admission rejection reasons and probe success. Do not assume hostNetwork or node-origin traffic is filtered identically. |
| P3 | Validate identity/scope decisions and quotas across replicas/workers. | Gateway route `/analyze`; both replicas; IdP; distributed quota store | Identity owner and platform engineer | Execute the approved matrix: missing/invalid/expired token → deny; wrong audience/issuer or missing scope → deny; analyst scope → allow; spoofed identity/X-API-Key → no bypass. A staging harness using secret-manager credentials in memory sends quota+1 requests distributed over both replicas; verify the configured global limit, Retry-After and independent per-actor buckets. | Status-only test report with approved opaque actor IDs, token values excluded, backend distribution and limiter metrics. Verify direct backend access is blocked. |
| P4 | Verify secret provenance, sync, encryption and rotation without exposing values. | Manager ARN; Kubernetes `ai-devsecops-api`; Deployment `ai-devsecops-demo` | Cloud administrator and platform engineer | Run the operator-only sync procedure below after authorization. `kubectl --context "$CTX" -n ai-devsecops get secret ai-devsecops-api -o jsonpath='{.metadata.name}{" "}{.metadata.resourceVersion}'` is metadata-only. Verify encryption-at-rest and audit policy using platform evidence. Restart and wait for rollout during a coordinated rotation window; test every replica with old/new credentials using an in-memory harness. | Secret version ID, resourceVersion, operator identity, rollout completion, new-key success/old-key denial, no-value log checks and rollback plan. Never attach Secret JSON/YAML or environment dumps. |
| P5 | Verify S3 log delivery, encryption, versioning, KMS permission boundaries and retention on real objects. | Artifact/log buckets; KMS `artifacts`; representative existing and test objects | Cloud administrator and data owner | Commands B1–B3 below; after authorization generate a synthetic bucket request and locate its delivered log record. Test authorized and unauthorized reader/publisher roles. Inventory existing objects/versions and compare expected KMS key IDs; new defaults do not rewrite old objects. | Delivered record/time and source identity, key metadata/rotation evidence, least-privilege allow/deny results, version recovery test, retention approval, existing-object migration completion. Best-effort delivery needs a bounded observation window and escalation if absent. |
| P6 | Verify privacy in all log paths, including failure and rejected requests. | App stdout, gateway access/error logs, WAF, tracing/APM, collectors, Kubernetes audit logs | Observability engineer and security owner | Follow the synthetic-marker protocol below; search every sink over ingestion lag plus retention buffering. Include 200, 401/403, 413, 422, 429 and controlled error cases, and failed-secret-sync telemetry. | Per-sink query/time range/record count, configuration identity and reviewer; zero marker occurrences in server-side sinks. Missing access to a sink is an unresolved check, not a pass. |
| P7 | Confirm the running image and rollback capability. | Deployment/pods, registry manifest and signed release records | Release/platform engineer | `kubectl --context "$CTX" -n ai-devsecops get pods -l app=ai-devsecops-demo -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[*].imageID}{"\n"}{end}'`; compare platform digests with the approved registry manifest. Exercise health, non-root/read-only behavior and rollback in staging. | All pod imageIDs match approved platform content; rollout/health/rollback evidence and no public exposure before remaining P checks pass. |

### Future secret synchronization and rotation

Provision the key in Secrets Manager through an approved secure UI or automation;
do not put the value in shell arguments, Terraform variables/state, tickets or Git.
Prefer existing platform secret-sync tooling when available. The repository helper
is suitable for an approved operator workflow without installing a new controller:

```bash
# MUTATING: instructions only; requires separate deployment authorization
python scripts/sync_api_secret.py --secret-id "$SECRET_ARN" --context "$CTX"
```

The helper retrieves AWSCURRENT into memory and passes a Secret manifest over stdin
to a fixed kubectl invocation. It captures tool output and emits generic errors.
Trust and verify the host/PATH/tool binaries; disable shell/terminal/CI recording.
Restrict IAM to this secret and necessary KMS decrypt, and cluster privileges to the
approved namespace/Secret. Kubernetes create permission cannot generally be scoped
to one resource name; use an approved bootstrap operator, then narrow update rights.

Rotation requires a coordinated maintenance window because the app accepts one key
loaded at startup: close new gateway traffic, generate/promote a new manager version,
sync, restart/wait for all replicas, update authorized consumers, test old-key denial
and new-key acceptance, then reopen traffic. Retire the prior version according to
policy. For suspected compromise, revoke immediately and accept downtime. Do not
roll back to a compromised key. Reusing a gateway/IdP for user identity avoids
distributing the backend shared key to every user.

### Future S3 and KMS verification commands

Use approved object names containing no sensitive values. Commands below are
read-only; any synthetic object creation or restoration is separately authorized.

```bash
# B1: repeat appropriate calls for both buckets
aws s3api get-bucket-logging --bucket "$ARTIFACT_BUCKET"
aws s3api get-bucket-versioning --bucket "$ARTIFACT_BUCKET"
aws s3api get-bucket-encryption --bucket "$ARTIFACT_BUCKET"
aws s3api get-public-access-block --bucket "$ARTIFACT_BUCKET"
aws s3api get-bucket-ownership-controls --bucket "$ARTIFACT_BUCKET"
aws s3api get-bucket-lifecycle-configuration --bucket "$LOG_BUCKET"

# B2: key metadata, never key material
aws kms describe-key --key-id "$KMS_KEY_ARN" --query 'KeyMetadata.{Arn:Arn,Enabled:Enabled,Manager:KeyManager}'
aws kms get-key-rotation-status --key-id "$KMS_KEY_ARN"

# B3: select a non-sensitive test object; repeat against inventory of older versions
aws s3api head-object --bucket "$ARTIFACT_BUCKET" --key "$TEST_OBJECT_KEY" \
  --query '{Encryption:ServerSideEncryption,KMS:SSEKMSKeyId,Version:VersionId,BucketKey:BucketKeyEnabled}'
```

Inspect log objects only in a restricted environment: their paths, user agents and
request metadata can be sensitive. Log delivery is not a complete audit guarantee;
verify existing CloudTrail coverage if completeness is required. Retention counts
current and noncurrent version age separately; total retention can exceed 365 days.
KMS request/storage costs, loss of access on key deletion, legal holds and ACL
compatibility all require explicit decisions before a Terraform apply.

### Synthetic log verification protocol

Use a fresh synthetic marker such as a UUID, never a real secret or historical
fixture value. Through an approved staging client, place it separately in a prompt,
query, `X-API-Key`, `Authorization`, cookie, unmatched path and malformed request.
Actual authentication, when needed, comes from an in-memory secret-manager client;
do not put real tokens in curl arguments. Record only marker, route, status and time.
Query app, proxy access/error, WAF samples, APM/traces, collectors and cluster audit
logs for the marker. Zero matches is required outside the test client and its
restricted evidence store. Also search failed sync/operator logs using a simulated
tool failure. Do not intentionally break a real key merely to test logging.

The app's current tests cover application records and responses. They do not prove
external proxies avoid body capture, audit policies avoid Secret payloads, or
collectors redact before storing. Confirm emitter allowlists and retention controls
even when a particular marker search returns zero results.

## Exceptions and security dispositions awaiting owners

No exception below is approved. No scanner suppression or blanket approval was
added. Attach approver identity/authority, exact scope, rationale, compensating
controls, evidence, expiry/review date, remediation trigger and ticket to any future
decision. A rejected exception requires an architecture change and new validation.

| ID | Finding and exact scope | Reason and proposed treatment | Responsible role | Validation and evidence required |
|---|---|---|---|---|
| X1 | Trivy `AWS-0089`, `terraform/main.tf`, `aws_s3_bucket.access_logs` | Logging the log sink into itself recurses. Retain the unlogged dedicated sink only if the owner accepts the audit design; evaluate an existing alternative audit sink/CloudTrail. | Cloud security owner with audit/data owner | P5 plus source-to-destination diagram proving no recursion, sink access controls and approved alternative audit coverage; explicit time-bounded exception. |
| X2 | Trivy `AWS-0132`, same file, `aws_s3_bucket_server_side_encryption_configuration.access_logs` | Direct S3 server-access-log delivery requires SSE-S3. Artifact data remains SSE-KMS. If all logs must be KMS-encrypted, select a compatible logging pipeline rather than accepting silently. | Cloud security owner and data owner | Review [AWS log destination requirements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html), P5 encryption/delivery evidence, restricted log access and retention; explicit exception or approved replacement design. |
| X3 | Bandit LOW `B404`, `scripts/sync_api_secret.py:9`; call-site `B603` annotation | Subprocess is necessary for the existing operator CLI workflow. Fixed tools, no shell, captured output, stdin values and timeout mitigate injection/exposure; compromised PATH/binaries remain a risk. | Application security owner | Review function `run_tool`, run `pytest tests/test_production_controls.py`, verify trusted CLI path/version/signatures and tests for error redaction. Record a reviewed finding disposition; do not treat the inline annotation as approval. |
| X4 | Gitleaks `hashicorp-tf-password`, `examples/insecure/bad-main.tf:21`, commits `50c01ec5b34fd0fbffcc8a0bcac89b554845b652` and `11f38303019a6bd679c394093567b90ed0146989` | Both exact assignments match the current teaching fixture. This establishes equality and location, not non-use. | Repository maintainer, credential-system owner and security owner | Obtain author attestation and creation/use records; privately compare against authorized credential inventories/history without exporting values or reusable hashes. Check related deployments, CI history and access records for reuse. Record scope/gaps and reviewer. If provenance cannot be established, treat as potentially exposed, revoke/rotate affected credentials and authorize incident/history remediation separately. Never test the literal against live systems. |
| X5 | Demo scanner HIGH `TF-AWS-S3-POL-001`, `terraform/main.tf`, `aws_s3_bucket_policy.artifacts` and `.access_logs` | The text matcher flags wildcard Principal inside explicit Deny-insecure-transport statements. Those statements do not grant public access. Preserve the deny policies. | Application/cloud security owner | Review parsed policy Effects/conditions, compare Trivy semantic results and P5 IAM/access tests; approve a scoped false-positive disposition or implement/test an Effect-aware detector. No global Principal exception. |
| X6 | Five candidate-image HIGH reviews in `docs/sqlite-openssl-dispositions.md` and `reports/cve-review-manifest.json`; fresh Alpine scan has zero feed matches | Release-specific history and live package policy show no fixed 3.24 package; affected SQLite features and QUIC symbols remain. Tested API routes do not use them, but bounded non-reachability is not an approved disposition. | Product security owner and release engineer | Obtain supported fixes/backports or review precise applicability evidence; rebuild/test/scan and record exact digest. Check OpenSSL's planned December 1 release and Alpine packaging. Any exception requires separate authorization. |

## Remaining decisions and go or no go checklist

Decisions still required: named accountable owners; target AWS account/region and
cluster/context; approved registry/repository/platform and immutable release digest;
image vulnerability policy and residual dispositions; public versus internal API,
DNS/controller/CA/renewal and internal TLS policy; CNI selectors and admission policy;
secret ARN/KMS/operator access and rotation window; IdP role/scope mapping and quota
values; bucket names/state backend/KMS grants/ACL migration/retention/legal holds and
existing-object re-encryption; audit/log sinks and access; X1–X6 dispositions and dates.

For **authorization to deploy into a controlled target for verification**:

- [ ] Candidate image, source snapshot, scans, SBOM and provenance are linked; no unresolved image release-policy violations.
- [ ] L1–L5 completed for that candidate; E1–E7 values/designs reviewed; placeholder check passes.
- [ ] Required X dispositions signed by authorized owners, or the causes removed and rescanned.
- [ ] Protected state/migration/backup and rollback plans reviewed; change authorization exists.
- [ ] Controlled rollout plan keeps public traffic closed until P1–P7 evidence is accepted.

For **production traffic approval after that deployment**:

- [ ] P1–P7 pass against the exact target and running image, with evidence and reviewers.
- [ ] Every live secret/log sink/certificate and network/auth/quota control is verified; no missing evidence is marked passed.
- [ ] Security, platform, cloud/data and release owners accept their controls and remaining approved risks.

Any unchecked required box means **NO GO** for that phase. Local green tests alone
cannot change this decision.
