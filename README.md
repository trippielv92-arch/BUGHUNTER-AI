# BugHunter AI — authorized security research desktop

BugHunter AI is a local-first security research workspace. It helps organize programme policy, manually approved scope, passive asset discovery, endpoint inventory, vulnerability assessment planning, potential findings, evidence and reports.

**It is not an autonomous exploit framework or a production multi-computer platform.** Automated hunts currently perform passive DNS/Certificate Transparency discovery and bounded, same-host HTTPS GET website discovery. Vulnerability-specific scenarios are created as manual review tasks; the worker does not run exploit payloads or confirm vulnerabilities.

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

1. Create a project using the official programme URL.
2. Analyze the public programme page or paste policy text.
3. Review the policy and extracted asset candidates yourself.
4. Add only exact hostnames that the programme explicitly authorizes.
5. Check exclusions and testing restrictions, then approve the exact included scope.
6. Select an approved HTTPS target and click **START HUNT**.
7. Review newly discovered candidate hosts, endpoints, manual assessment tasks and potential findings.
8. Verify findings manually within the programme rules; export a report when ready.

Scope approval is a human decision. Discovered hosts are never automatically included or approved. Wildcards are not expanded into authorization.

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

The background worker currently requires the same local SQLite database as the desktop. It does not yet provide central API/PostgreSQL execution across multiple computers. If you override `BUGHUNTER_DATA_DIR` or `BUGHUNTER_DATABASE_URL`, make sure the worker service is configured to use the identical database location before relying on background execution.

## What an automated hunt currently does

- Revalidates the project's active status and manually approved scope.
- Resolves DNS for included and approved assets.
- Optionally queries Certificate Transparency for names related to approved assets.
- Saves discovered names as candidates with `included=False` and `approved=False`.
- Revalidates the exact target before bounded website discovery.
- Uses rate-limited HTTPS GET requests, same-host boundaries and bounded response handling.
- Inventories discovered pages, forms, JavaScript references and documented API operations where available.
- Creates metadata-driven manual assessment recommendations for discovered endpoints.
- Correlates existing observations with potential findings without sending extra requests or payloads.
- Persists progress, checkpoints, results and job status in the local database.

The current hunt page/request limit is bounded (maximum 25). Website discovery does not follow redirects. Certificate Transparency lookups contact `crt.sh`; discovered target hosts are not probed unless individually reviewed and approved later.

## Safety and authorization boundaries

- Test only assets explicitly authorized by the relevant programme.
- Exclusions and programme restrictions take precedence; review the official policy before approving scope.
- New DNS/CT names are candidates only. They are not authorization.
- The automated hunt does not run SQL injection, XSS, IDOR, SSRF, authentication bypass, payment, race-condition or other exploit payloads.
- Sensitive authentication, authorization, IDOR, SSRF, injection and business-logic checks remain manual and require approved test accounts, synthetic data or a controlled environment.
- Potential findings are not automatically confirmed. Correlation is supporting evidence only.
- Do not put credentials, session tokens or other secrets in the target URL. Hunt creation rejects query strings for this reason.

No findings does not mean a target is secure. A discovery run is not a comprehensive security assessment.

## Implemented foundation

- Native PySide6 desktop interface and local owner login.
- SQLAlchemy persistence and per-account project data isolation.
- Programme URL retrieval, manual policy text analysis and candidate extraction.
- Exact included-asset scope approval gate.
- Passive DNS and Certificate Transparency discovery with unapproved candidate handling.
- Bounded website crawling and endpoint/API documentation inventory.
- Metadata-driven manual assessment planning.
- Potential findings, evidence records, finding correlation and report export.
- Persistent local job queue and systemd background worker integration.
- Job progress polling, cooperative stop requests and restart recovery from the beginning.

## Still under development

- Policy-aware exclusions, wildcard/CIDR semantics, expiry and rate-limit enforcement.
- True pause/resume and exact mid-hunt checkpoint recovery.
- Deeper permission-gated vulnerability verification using controlled test accounts.
- Stronger finding deduplication, review workflow and evidence lifecycle.
- Central server/API with PostgreSQL and multi-computer workers.
- Further security hardening, integration tests, packaging and operational monitoring.

## Data and privacy

The default SQLite database is stored under `data/bughunter.db` (overridable with `BUGHUNTER_DATA_DIR` or `BUGHUNTER_DATABASE_URL`). Passwords are Argon2-hashed. The database and evidence are not encrypted at rest. Activity records are persistent but not tamper-evident. Cloud AI is not configured.

## Requirements

Python 3.10+, Parrot OS with a graphical desktop session, systemd user services for persistent hunts, and network access for programme retrieval and authorized discovery. PySide6 may require distro Qt/XCB runtime libraries.
