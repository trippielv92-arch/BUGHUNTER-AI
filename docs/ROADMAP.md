# Product roadmap

## Product definition

BugHunter AI is one cloud-connected Parrot desktop client backed by an authenticated API, a PostgreSQL source of truth and a persistent background hunt worker. Do not reintroduce a second normal local workspace or duplicate project stores.

## Implemented foundation

- [x] Parrot desktop sign-in to the central API.
- [x] Authenticated API with Argon2 account passwords and short-lived JWTs.
- [x] Account-scoped projects and project resources.
- [x] Programme policy analysis, candidate review and exact human-approved scope.
- [x] Durable cloud hunt jobs and a separate worker process.
- [x] Passive DNS/Certificate Transparency candidate discovery.
- [x] Bounded same-host HTTPS discovery and endpoint/API inventory.
- [x] Evidence records, potential findings and conservative correlation.
- [x] Debian packaging workflow for Parrot Linux.

## Release gates — do these in order

1. **Runtime readiness:** prove the production health endpoint, account login, database reads/writes and worker startup with a harmless test job.
2. **Single-workspace cleanup:** keep cloud mode as the normal UI and launcher; make local SQLite developer-only; keep README, setup scripts and package behavior consistent.
3. **Worker reliability:** health heartbeat, lease/heartbeat recovery, bounded retries, cancellation and safe restart semantics.
4. **Vulnerability verification:** implement explicit, scope-gated, non-destructive checks with controlled test accounts or synthetic data; preserve request/response evidence and confidence rationale.
5. **Finding quality:** deterministic deduplication, reproducible verification steps, evidence integrity, review/confirmation lifecycle.
6. **Security hardening:** [x] enable RLS on all 15 application tables and revoke public-role table grants; complete second-account tenant-isolation tests, secrets rotation, encrypted backups, audit integrity and monitoring.
7. **Release:** build and install the Debian package on Parrot, smoke-test login/project/scope/hunt/results, publish a versioned artifact and update installation instructions.

## Non-negotiable safety requirements

- Scope exclusions always override inclusions.
- A discovered asset is never authorization.
- Require explicit approval before testing a target.
- No destructive, state-changing or high-impact tests without explicit authorization and controlled test data.
- Never mark a finding confirmed solely from a heuristic or response difference.
- Never claim a hunt resumed at an exact checkpoint unless that checkpoint was actually restored.

## Current release-hardening branch

The `release/hardening-v0.4.0` branch adds the following regression-protected changes:

- [x] Bound transient hunt retries to three total attempts, with short backoff between retries.
- [x] Persist retry count in the existing durable job input; no schema migration is required.
- [x] Keep transport/database exception text out of job records because it can contain secrets or request details.
- [x] Include finding category in exact duplicate identity so different vulnerability classes on the same asset are not collapsed.
- [x] Add two-account project/child-record isolation regression tests.
- [x] Add finding identity/correlation, evidence-tamper, assessment-planner, tenant-isolation, heartbeat and retry-boundary regression tests.
- [ ] Obtain a passing full CI run and inspect the generated Debian package.
- [ ] Verify production API, worker, database connectivity and account isolation against the deployed environment.
- [ ] Complete worker heartbeat/lease observability and controlled retry recovery for process/database interruption.
- [ ] Extend automated vulnerability verification only where a controlled test account or researcher-owned synthetic resource provides safe proof. Heuristic indicators remain potential findings, never automatic confirmations.

These changes are hardening work, not a claim that the final release gates have passed.

## Production database inspection — 2026-11-24

The linked Supabase project is reachable and reports `ACTIVE_HEALTHY`. Inspection found 15 public application tables and RLS enabled on all 15. Direct table privileges for the Supabase `anon` and `authenticated` roles were absent for the checked project and finding tables, consistent with the private API-only database architecture. Supabase's RLS-without-policy advisory is therefore expected only while those public roles remain unprivileged; do not add broad public policies to silence it.

The database currently reports no recorded migration history. The application has startup schema creation/compatibility logic, but production deployment still needs a successful API/worker startup test against this exact schema and confirmation that the configured API and worker connections use the intended private database role. No production DDL was changed during this inspection.
