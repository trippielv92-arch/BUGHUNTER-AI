# BugHunter AI — authorized security research desktop

BugHunter AI is a local-first security research workspace. It helps organize programme policy, manually approved scope, passive asset discovery, endpoint inventory, vulnerability assessment planning, potential findings, evidence and reports.

**Important capability boundary:** the current automated hunt performs passive DNS/Certificate Transparency discovery, bounded same-host HTTPS GET website discovery, endpoint inventory and evidence correlation. It does not yet perform comprehensive vulnerability-specific verification or run exploit payloads. See the cloud deployment guide for the cloud-worker foundation and current limitations.

## Install on Parrot OS

Extract the project, open a terminal in `BUGHUNTER-AI`, then run:

```bash
chmod +x scripts/*.sh
./scripts/setup_parrot.sh
./scripts/run_parrot.sh
```

First launch: create the local owner account with a username and password of at least 12 characters, then log in. There is no default account.

Run the test suite:

```bash
source .venv/bin/activate
PYTHONPATH=. pytest -q
```

## Standard workflow

1. Create a project using the official programme URL. In the remote workspace, the URL is automatically retrieved and analyzed after project creation.
2. For a private or inaccessible programme, paste/import its official policy text and run analysis; provider passwords are never requested.
3. Review extracted in-scope, excluded and ambiguous candidates, along with testing restrictions and reward/eligibility clauses.
4. Use **AUTO-PROPOSE CLEAR IN-SCOPE HOSTS** to add only exact hostnames with clear inclusion evidence to proposed scope. Wildcards, CIDRs, IPs, mobile identifiers and path-limited URLs are not broadened into hostname scope.
5. Review the complete proposed list and approve the exact included scope.
6. Click **START CLOUD HUNT** to queue a hunt for every approved host, or **START HUNT** in local mode.
7. Review newly discovered candidate hosts, endpoints, manual assessment tasks and potential findings.
8. Verify findings manually within the programme rules; export a report when ready.

Scope approval is a human decision. Policy-listed exact hostnames can be automatically proposed, but no asset is authorized until the complete scope is explicitly approved. Discovered DNS/CT names are never automatically proposed or approved. Wildcards are not expanded into authorization. A changed policy snapshot revokes previous scope approval.

## Persistent background hunts

The desktop **START HUNT** action creates a durable `Automated hunt` job in the local SQLite database and asks the user-level systemd service to start. The worker runs separately from the desktop, so closing the GUI does not stop a queued/running hunt.

Install the worker once from the project directory:

```bash
bash scripts/install_hunt_worker.sh
```

The installer creates and enables `bughunter-hunt-worker.service` for the current Linux user. The desktop attempts to start that service when a hunt is queued.

Useful service commands:

```bash
systemctl --user status bughunter-hunt-worker.service
systemctl --user restart bughunter-hunt-worker.service
journalctl --user -u bughunter-hunt-worker.service -f
```

The desktop polls the persisted job queue and shows status, percentage and the latest checkpoint. **STOP HUNT** marks the job stopped in the database; the worker checks that state between bounded DNS/HTTP operations and stops cooperatively.

If the worker process is interrupted while a job is running, it safely requeues that job from the beginning on its next startup. It does not pretend to resume at an exact mid-crawl checkpoint. Pause/resume and exact checkpoint continuation are not implemented yet.

The local worker uses the local SQLite database. For hunts that must continue after the Parrot computer is shut down, deploy the PostgreSQL-backed cloud API and worker described in [Cloud deployment](docs/CLOUD_DEPLOYMENT.md). The local SQLite workspace and cloud workspace are separate; projects are not silently synchronized between them.

## Cloud execution

A Docker Compose deployment is now provided for a Linux VPS. It runs PostgreSQL, the authenticated API and one persistent hunt worker as separate services. The API and worker share the same database and durable job queue. PostgreSQL row locking makes each job claim atomic; multi-worker lease/heartbeat recovery is not implemented yet.

See [docs/CLOUD_DEPLOYMENT.md](docs/CLOUD_DEPLOYMENT.md) for setup, secrets, TLS reverse-proxy requirements, desktop connection and account creation. This is deployable infrastructure configuration, not a cloud server that has already been provisioned.

## What an automated hunt currently does

- Revalidates the project's active status and manually approved scope.
- Resolves DNS for included and approved assets.
- Optionally queries Certificate Transparency for names related to approved assets.
- Saves discovered names as candidates with `included=False` and `approved=False`.
- Revalidates the exact target before bounded website discovery.
- Uses up to 100 bounded HTTPS GET requests per approved host, with same-host boundaries, robots.txt checks and bounded response handling.
- Checks a fixed set of common exposed configuration, repository, diagnostic and API-documentation paths; it does not brute-force directories and does not retain secret values.
- Performs up to 12 additional endpoint-specific, unauthenticated GET checks against discovered same-host API routes, within the same total request budget.
- Omits discovered query strings, cookies and credentials from those API checks; skips non-GET methods, templated object routes, risky action-like paths and robots-disallowed endpoints.
- Records 401/403 responses as access-control observations and flags only non-empty personal-data-like JSON field names from successful anonymous responses. It never stores response values and does not assume that a public endpoint is a vulnerability.
- Enforces parsed programme restrictions: explicit automated-scanning bans skip active crawling, broader bans on automated tools also skip passive discovery, and extracted request-rate limits increase inter-request delay.
- Inventories discovered pages, forms, JavaScript references and documented API operations where available.
- Creates metadata-driven manual assessment recommendations for discovered endpoints.
- Correlates existing observations with potential findings without sending extra requests or payloads.
- Persists progress, checkpoints, results and job status in the local database.

The current hunt page/request limit is bounded (maximum 100). Website discovery does not follow redirects. Certificate Transparency lookups contact `crt.sh`; discovered target hosts are not probed unless individually reviewed and approved later.

## Safety and authorization boundaries

- Test only assets explicitly authorized by the relevant programme.
- Exclusions and programme restrictions take precedence; review the official policy before approving scope.
- New DNS/CT names are candidates only. They are not authorization.
- The automated hunt does not run SQL injection, XSS, IDOR, SSRF, authentication bypass, payment, race-condition or other exploit payloads.
- The anonymous API check is not a credentialed authentication test. It does not compare researcher-owned user roles or prove that an endpoint should require login.
- Controlled authenticated authorization, IDOR, SSRF, injection and business-logic checks remain manual and require approved test accounts, synthetic data or a controlled environment.
- Potential findings are not automatically confirmed. Correlation is supporting evidence only.
- Do not put credentials, session tokens or other secrets in the target URL. Hunt creation rejects query strings for this reason.

No findings does not mean a target is secure. A discovery run is not a comprehensive security assessment.

## Implemented foundation

- Native PySide6 desktop interface and local owner login.
- SQLAlchemy persistence and per-account project data isolation.
- Automatic programme-page analysis on remote project creation, with private-programme policy-text import.
- Known-provider identification plus generic policy parsing for other programme URLs.
- Structured extraction of inclusion/exclusion candidates, path-limited URLs, wildcard/CIDR/IP assets, mobile app identifiers, eligibility/reward clauses and testing restrictions.
- One-click proposal of clear exact-host candidates, stale-policy candidate rejection and policy-change scope-approval revocation.
- Programme-aware automated-tool prohibitions and conservative request-rate enforcement.
- Exact included-asset scope approval gate.
- Passive DNS and Certificate Transparency discovery with unapproved candidate handling.
- Bounded website crawling and endpoint/API documentation inventory.
- Metadata-driven manual assessment planning.
- Potential findings, evidence records, finding correlation and report export.
- Persistent local job queue and systemd background worker integration.
- Job progress polling, cooperative stop requests and restart recovery from the beginning.

## Still under development

- Provider-specific API adapters, JavaScript-rendered policy-page support and authenticated browser-session import.
- Complete wildcard/CIDR/path-aware authorization semantics, programme expiry handling and stronger interpretation of complex rate-limit clauses.
- True pause/resume and exact mid-hunt checkpoint recovery.
- Deeper permission-gated vulnerability verification using controlled test accounts.
- Stronger finding deduplication, review workflow and evidence lifecycle.
- Managed cloud hosting, TLS ingress, encrypted backups and operational monitoring.
- Authenticated browser-session import for private programmes (policy-text import is supported as the safer current fallback).
- Further security hardening, integration tests, packaging and operational monitoring.

## Data and privacy

The default local SQLite database is stored under `data/bughunter.db` (overridable with `BUGHUNTER_DATA_DIR` or `BUGHUNTER_DATABASE_URL`). Cloud mode uses PostgreSQL. Passwords are Argon2-hashed. Database and evidence encryption at rest, encrypted backups and tamper-evident audit logs require additional deployment hardening. Private-programme policy text can be pasted/imported without saving provider passwords or session cookies.

## Requirements

Python 3.10+, Parrot OS with a graphical desktop session, systemd user services for persistent hunts, and network access for programme retrieval and authorized discovery. PySide6 may require distro Qt/XCB runtime libraries.
