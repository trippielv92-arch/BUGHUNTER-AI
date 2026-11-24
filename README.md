# BugHunter AI

**BugHunter AI is a cloud-connected desktop workspace for authorized bug-bounty research.** The Parrot Linux application is the single user interface. Accounts, projects, approved scope, hunt jobs and findings are stored by the central API and PostgreSQL database. A separate cloud worker processes queued hunts, so closing the desktop does not stop them.

## The one supported user workflow

1. Install and open BugHunter AI on Parrot Linux.
2. Sign in with the account provisioned for the central service.
3. Create a project and enter its official programme URL.
4. Review the programme policy, exclusions and extracted asset candidates.
5. Accept only assets clearly in scope, then explicitly approve the exact scope.
6. Start a cloud hunt. The cloud worker continues independently of the desktop.
7. Review discovered assets, endpoints, assessment leads and evidence-backed findings.

**Scope approval is mandatory.** Newly discovered DNS or Certificate Transparency names are candidates only; they are never automatically authorized. Programme exclusions and testing restrictions take precedence.

## What a hunt currently does

The current automated hunt provides bounded, policy-aware discovery:

- Revalidates the project's active status and exact approved scope.
- Resolves approved assets and optionally gathers related Certificate Transparency names as unapproved candidates.
- Performs bounded same-host HTTPS GET discovery and inventories pages, forms, JavaScript references and documented API operations.
- Checks a fixed set of common exposed configuration, repository, diagnostic and API-documentation paths without directory brute forcing.
- Records limited anonymous and researcher-owned test-account GET observations for supported API routes.
- Produces assessment recommendations and correlates observations into potential findings.
- Persists job state and progress in the cloud database for the background worker and desktop to share.

### Important capability boundary

This release is **not yet a comprehensive autonomous vulnerability scanner**. It does not automatically prove SQL injection, XSS, SSRF, IDOR/BOLA, authentication bypass, race conditions, payment flaws or business-logic vulnerabilities. It does not run destructive or state-changing exploit tests. Potential findings require human review and independent verification. A clean hunt is not proof that a target is secure.

## Architecture

- **Desktop:** PySide6 application; sign-in, projects, programme policy, exact scope approval, hunt controls and results.
- **API:** FastAPI service; authentication, account isolation, project data and durable job creation.
- **Database:** Supabase PostgreSQL; shared persistent source of truth.
- **Worker:** persistent cloud daemon; claims and processes queued hunts independently of the desktop.
- **Packaging:** Debian package for Parrot Linux; the package is a client for the central service, not a separate cloud installation.

There is one normal cloud workspace. The old local SQLite workspace remains available only as an explicit developer option by setting `BUGHUNTER_ENABLE_LOCAL_MODE=1`; it is not part of the normal Parrot user flow.

## Install on Parrot Linux

Download the latest `BugHunter-AI-Parrot-DEB` artifact from the successful [Build Parrot DEB workflow](https://github.com/trippielv92-arch/BUGHUNTER-AI/actions/workflows/build-deb.yml), then install the downloaded package:

```bash
sudo apt install ./bughunter-ai_<version>_all.deb
```

Launch **BugHunter AI** from the application menu or run:

```bash
bughunter-ai
```

The first cloud account is provisioned by an administrator using the local CLI command `bughunter-ai-admin create-account --username YOUR_USERNAME`. The CLI prompts for the password and stores an Argon2 password hash; do not insert plaintext passwords into SQL.

For a source checkout:

```bash
./scripts/setup_parrot.sh
./scripts/run_parrot.sh
```

The source launcher uses the same central cloud API as the Debian package.

## Cloud operations

- Production API: `https://bughunter-ai-ebon.vercel.app`
- Health endpoint: `/health`
- Deployment configuration: [Vercel + Supabase guide](docs/VERCEL_SUPABASE_DEPLOYMENT.md)
- Worker and VPS alternative: [Docker Compose cloud guide](docs/CLOUD_DEPLOYMENT.md)

Cloud readiness must be verified from live API health, authenticated account login, database connectivity and an observed worker job before treating the service as operational. A deployment marked READY only confirms deployment completion; it does not prove all runtime services are healthy.

## Safety and data handling

- Use only programmes and assets for which you have explicit authorization.
- Scope exclusions always override inclusions.
- Discovered assets remain unapproved until a human reviews and approves them.
- Use only researcher-owned test accounts and synthetic records for permission testing.
- Credentials are stored as encrypted profiles; never put tokens or passwords in target URLs.
- Findings remain potential until evidence is reviewed and confirmed.
- The cloud service stores account, project, scope, job and finding data centrally. Keep API and database secrets out of source control and chat.

## Current limitations

- Vulnerability-specific verification is still a development milestone.
- Exact mid-hunt pause/resume and checkpoint continuation are not complete.
- Cloud worker health monitoring, retry/lease recovery and production backups need further hardening.
- Supabase RLS is disabled on application tables. Direct table privileges for `anon`, `authenticated` and `PUBLIC` have been revoked, and the backend uses a role with `BYPASSRLS`; this is defense-in-depth work that still needs a reviewed policy/migration before production multi-tenant use.
- Free-tier hosting limits and database inactivity policies are not suitable for an availability guarantee.

See [the product architecture and completion gates](docs/PRODUCT_ARCHITECTURE.md) and [the roadmap](docs/ROADMAP.md).
