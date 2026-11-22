# BugHunter AI — Personal desktop MVP

This is an actual, limited working MVP—not the complete autonomous research product described in the master specification.

## Install on Parrot OS
Extract the ZIP, open a terminal in `BUGHUNTER-AI`, then run:
```bash
chmod +x scripts/*.sh
./scripts/setup_parrot.sh
./scripts/run_parrot.sh
```
First launch: enter an owner username and password of at least 12 characters, click **CREATE OWNER ACCOUNT**, then log in. No default account exists.

Run tests:
```bash
source .venv/bin/activate
PYTHONPATH=. pytest -q
```

## Current workflow
1. Create a project with an HTTPS programme URL.
2. Select it, then analyze the public page or paste policy text manually.
3. Treat extracted hostnames as candidates only; verify programme rules yourself.
4. Add only hostnames you are explicitly authorized to test.
5. Approve scope manually.
6. Start the limited safe checks after confirmation.
7. Export JSON, Markdown, HTML or PDF report.

## Implemented
- Native PySide6 dark desktop interface.
- Local first-owner account creation and login; Argon2 password hashing.
- SQLAlchemy/SQLite persistence for projects, assets, findings, checks and activity.
- HTTPS-only programme page retrieval and manual policy text analysis.
- Candidate hostname extraction and policy keyword excerpts.
- Explicit scope approval gate and hostname boundary helper.
- One non-destructive HTTPS GET per approved hostname; observes HTTP status and common security headers. Missing headers create low-confidence **potential** findings only.
- Persistent check and activity records.
- JSON, Markdown, HTML and PDF report export.
- Unit tests.

## Important limitations
This is not a comprehensive scanner. No subdomain/DNS discovery, port scanning, crawling, authenticated testing, SQLi/XSS/IDOR/SSRF exploitation, ZAP/Nuclei, AI, background worker queue, pause/resume, crash recovery, automatic backups, finding verification workflow, full scope exclusion editor, wildcard/CIDR enforcement, programme expiry/rate-limit enforcement, encryption at rest, inactivity lock, recovery flow, or Windows installer is implemented. See `docs/ROADMAP.md`.

The scanner only performs a basic HTTPS GET and reads response headers. It does not follow target redirects. Do not test assets without explicit programme authorization. Scope extraction is advisory and never approves assets automatically. No findings does not mean the target is secure.

## Data and privacy
SQLite database is stored at `data/bughunter.db` (override with `BUGHUNTER_DATA_DIR` or `BUGHUNTER_DATABASE_URL`). Passwords are Argon2-hashed. This MVP does not encrypt the database or evidence at rest. Cloud AI is not configured and target data is not sent to an AI provider. Activity records are persistent but not tamper-evident.

## Requirements
Python 3.10+, Parrot OS with a graphical desktop session, and network access for optional programme retrieval / approved checks. PySide6 may need Qt/XCB runtime libraries from your distro if the GUI cannot start.

## Passive reconnaissance CLI

Run passive DNS resolution and Certificate Transparency discovery for a
project whose scope and assets have been reviewed:

```bash
.venv/bin/python -m app.cli passive-recon --project-id 1
```

Run DNS resolution only, without contacting the Certificate Transparency
service:

```bash
.venv/bin/python -m app.cli passive-recon --project-id 1 --no-ct
```

Discovered names are saved as scope candidates with `included=False` and
`approved=False`. Review each candidate against the actual bounty policy before
manually including and approving it. This module does not probe discovered
hosts or authorize testing.

## Passive reconnaissance CLI

Run passive DNS resolution and Certificate Transparency discovery for a
project whose scope and assets have been reviewed:

```bash
.venv/bin/python -m app.cli passive-recon --project-id 1
```

Run DNS resolution only, without contacting the Certificate Transparency
service:

```bash
.venv/bin/python -m app.cli passive-recon --project-id 1 --no-ct
```

Discovered names are saved as scope candidates with `included=False` and
`approved=False`. Review each candidate against the actual bounty policy before
manually including and approving it. This module does not probe discovered
hosts or authorize testing.
# BUGHUNTER-AI
