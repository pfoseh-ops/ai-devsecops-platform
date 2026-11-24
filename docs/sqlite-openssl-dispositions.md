# SQLite/OpenSSL disposition follow-up

Raw scan evidence, generated manifests and image archives are intentionally excluded from Git. References to `reports/` identify local review evidence, not committed files. CI produces fresh validation artifacts; retrieve local evidence through an authorized channel when required.

2026-11-24. **NO GO. Investigation completed; all five remediation/disposition
gates remain open.** A fresh rebuild and repository query found no compatible
fixed binary package in the configured Alpine 3.24 repositories. No exception,
false-positive disposition or production approval has been granted.

## Exact image and components

All five rows below refer to the same tested linux/amd64 image:

- Local tag: `ai-devsecops-readiness:cve-review`.
- Local image/index digest: `sha256:a2a1da27fa1341057f33632bd7cbe49e61b1b8e7419e45c0cf474ebb2b2f5474`.
- Image configuration digest: `sha256:2528b06876a60c2a04b9ccc0b3a6b5fd7f1eaececb6d8392c7e25ed44c112d4e`.
- Base remains `python:3.12-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`.
- OS Alpine 3.24.4, CPython 3.12.16. No published or approved registry digest exists.

The previous `:alpine` image was preserved. The new digest identifies the fresh
`--no-cache --pull` build; changed build metadata does not imply a vulnerability fix.
The manifest (local-only evidence: `reports/cve-review-manifest.json`) checks the scanned and inspected
image layer lists, includes package layers and binds evidence to this exact image.

`sqlite-libs` **3.53.4-r0** supplies `/usr/lib/libsqlite3.so.3.53.4`, exposed to
Python through the optional `sqlite3`/`_sqlite3` standard-library extension. No
application component in `src/app` or `src/ai_guard` uses SQLite. It remains usable
by code inside the container, which is why absence of an API SQL route does not
establish package safety.

`libssl3` **3.5.9-r1** supplies `/usr/lib/libssl.so.3`, with `libcrypto3` **3.5.9-r1**
as a dependency. Python `_ssl`/`ssl` and the asyncio/Uvicorn stack load these
libraries. Uvicorn is configured for HTTP over TCP, without TLS/QUIC options;
the health check uses HTTP on loopback. TLS termination remains external and
deployment-dependent. Loading libssl is not the same as calling its QUIC API.

## Alpine advisory and changelog results

The [Alpine v3.24 main security database](https://secdb.alpinelinux.org/v3.24/main.json)
contains none of these five IDs at the recorded retrieval time. That is an advisory
coverage gap, not a statement of non-applicability. Public source snapshots, hashes,
timestamps and the latest 20 path-specific commits are saved under
`reports/alpine-cve-sources` (local-only evidence: `reports/alpine-cve-sources/summary.json`).

The SQLite branch history ends at [upgrade to 3.53.4, August 21](https://github.com/alpinelinux/aports/commit/a9c3ba8b9129ec0f294d0a9bf538c2f1632bb016).
The [3.24 recipe](https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/sqlite/APKBUILD)
has `pkgrel=0`, uses the upstream 3.53.4 source and lists no local security patches
for these issues. The live `apk --no-cache policy` query offers only 3.53.4-r0.

OpenSSL's latest [November 18 backport commit](https://github.com/alpinelinux/aports/commit/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2)
raises the package to 3.5.9-r1 and adds patches for CVE-2026-88822, -88823, -95691,
-95692 and **-107496**, not **-107494** or -124709. The live repository query offers
only 3.5.9-r1. Neither a newer version nor a backport for the two requested QUIC
issues was evidenced in the [current branch recipe](https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/openssl/APKBUILD).

| CVE | Installed package | Fix/backport conclusion and source | Applicability and disposition |
|---|---|---|---|
| CVE-2026-119373 | sqlite-libs 3.53.4-r0 | Upstream fix in 3.54.0 according to the [vendor tracker and linked upstream commit](https://security-tracker.debian.org/tracker/CVE-2026-119373). Alpine's recipe/history and repository still supply unpatched 3.53.4-r0. | FTS5 is enabled and a benign FTS5 query succeeds. The affected feature is present; tested API paths make no SQLite connection. **OPEN: treat as affected pending a fixed package or reviewed applicability disposition.** |
| CVE-2026-119374 | sqlite-libs 3.53.4-r0 | Upstream 3.54.0 fix for the secure-delete FTS5 issue is recorded in the [tracker/upstream reference](https://security-tracker.debian.org/tracker/CVE-2026-119374); not backported in the reviewed Alpine recipe. | FTS5 and SECURE_DELETE build options are present. This alone does not establish every malicious-database trigger condition, but it prevents declaring the feature absent. No API accepts database files or executes SQL. **OPEN.** |
| CVE-2026-119379 | sqlite-libs 3.53.4-r0 | Upstream 3.54.0 fixes the changeset issue per the [tracker/upstream reference](https://security-tracker.debian.org/tracker/CVE-2026-119379). No Alpine 3.24 fixed package/backport found. | ENABLE_SESSION is present; the application has no changeset processing path. Native-library use remains possible inside the image. **OPEN.** |
| CVE-2026-107494 | libssl3 3.5.9-r1; libcrypto3 3.5.9-r1 dependency | The [tracker](https://security-tracker.debian.org/tracker/CVE-2026-107494) references an OpenSSL 3.5 branch fix, `734c6cd7444bdbf589bfec917e47598c1b21ddd3`, for an incomplete earlier QUIC fix. The direct commit page could not be retrieved during this review, so patch equivalence was not verified. Alpine's latest security commit does not include this ID. | QUIC client/server entry-point symbols exist in the actual libssl binary. No application QUIC path or datagram activity was found in the exercised routes. **OPEN: upstream fix reference exists; installed backport not evidenced.** |
| CVE-2026-124709 | libssl3 3.5.9-r1; libcrypto3 3.5.9-r1 dependency | The [OpenSSL November 17 advisory](https://openssl-library.org/news/secadv/20261117.txt) identifies 3.5 as affected and 3.5.10 as the fix, with release scheduled December 1, 2026. That date is future at this review. No matching Alpine backport found. | QUIC server symbol exists, but the configured application does not run a QUIC server. **OPEN: affected library feature retained; no reachable API path demonstrated.** |

The three SQLite fixes exist upstream; this does not make an Alpine 3.24 package
available. [SQLite's 3.54.0 release](https://sqlite.org/releaselog/3_54_0.html) is real,
but substituting a private source build would introduce a separately maintained
native component. No such binary was installed, nor were edge repositories mixed
into stable. The compatible vendor update path was exercised by the uncached
build's `apk upgrade --no-cache` and left all three package versions unchanged.

The HIGH labels are retained from the original scanner review. OpenSSL rates
CVE-2026-124709 Low upstream; that difference is documented, not used as an
automatic downgrade or approval.

## Reachability evidence and limitations

`probe-cve-reachability.py` (local-only evidence: `reports/probe-cve-reachability.py`) ran against the
actual rebuilt image, with no network, a read-only root filesystem, dropped
capabilities and no-new-privileges. Test tools were mounted separately after the
image's installed dependencies on `sys.path`.

It exercised `/`, `/health`, `/openapi.json` and `/analyze` with missing, blank,
oversized and combined-risk inputs. An audit hook would fail on SQLite connections
or Python datagram-socket creation during those paths. Both observed counts were
zero, and SQLite was not imported by the tested application. The hook was then
disabled for separate optional-component checks, which confirmed FTS5, SESSION,
the benign FTS query and both QUIC symbols. Library SHA-256 hashes and exact results
are in `cve-reachability.json` (local-only evidence: `reports/cve-reachability.json`).

Source search found no sqlite/QUIC/HTTP3/ctypes/subprocess/socket use in `src`,
configuration or the container command. The existing full API/scanner tests and
actual Uvicorn smoke test also passed. These are bounded observations, not whole-
program proofs: Python audit hooks do not intercept arbitrary native calls, a
future dependency/configuration can change reachability, and attacker code already
executing inside a container can directly load retained libraries. No malicious
database, changeset or QUIC exploit was executed. External proxy software is not
covered by this application-image review.

## Results, owners and completion evidence

Rebuilt image: **77 local tests passed (2 warnings), 66 isolated tests passed
(4 warnings)**. Ruff passed. Actual server health/analyze/log-redaction/shutdown
smoke and reachability probes passed. Trivy 0.76.2 at
`2026-11-24T08:54:17.519243071Z`: **0 vulnerabilities, 0 secrets**, 38 OS packages.
The database freshness check succeeded; metadata still shows updated November 24
01:05:31Z and next update November 25 01:05:31Z. Scanning does not close these manual
reviews. Exact commands (local-only evidence: `reports/cve-review-commands.md`),
scan (local-only evidence: `reports/cve-image-scan.json`), SBOM (local-only evidence: `reports/cve-image-sbom.cdx.json`),
inventory (local-only evidence: `reports/cve-runtime-inventory.json`) and the manifest are retained.

| Outstanding work | Responsible role | Evidence to close |
|---|---|---|
| SQLite three CVEs | Release engineer with Alpine/package maintainer; application security owner reviews | Supported Alpine update/backport with upstream patch mapping; runtime SQLite version/build identity; test and scan results tied to the rebuilt digest. Alternatively a reviewed base/runtime redesign, with explicit SQLite compatibility requirements. |
| OpenSSL two CVEs | Release engineer with Alpine/package maintainer; application security owner reviews | Vendor package including each requested fix, or patch-equivalence evidence; actual libssl version/hash; rebuilt digest and tests. Recheck the planned 3.5.10 release and subsequent Alpine packaging rather than assuming the schedule guarantees delivery. |
| Bounded non-reachability disposition | Application security owner and service owner | Review these exact code/configuration/library identities, supported API surface and native-code limitations; formally record any justified not-affected decision or separately authorized, expiring exception. No such decision is made here. |
| Production authorization | Platform, cloud and security owners | All existing readiness controls and approvals, including external TLS/logs, identity, distributed limits, CNI/admission, secrets and S3 controls. |

## Updated checklist

- [x] Identify all five exact installed components and image identity.
- [x] Check release-specific Alpine security data, package history and live package policy.
- [x] Rebuild without cache, test and scan; record feature presence and bounded reachability.
- [ ] Obtain/install verified supported fixes or authorized vulnerability dispositions for all five.
- [ ] Verify deployment controls and any necessary exceptions through authorized owners.

The available local investigation is complete. The five release gates cannot be
marked resolved on present evidence. **NO GO remains.** Nothing was deployed,
pushed, provisioned or approved.
