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
6. **Security hardening:** tenant-isolation review, database RLS/policies, secrets rotation, encrypted backups, audit integrity and monitoring.
7. **Release:** build and install the Debian package on Parrot, smoke-test login/project/scope/hunt/results, publish a versioned artifact and update installation instructions.

## Non-negotiable safety requirements

- Scope exclusions always override inclusions.
- A discovered asset is never authorization.
- Require explicit approval before testing a target.
- No destructive, state-changing or high-impact tests without explicit authorization and controlled test data.
- Never mark a finding confirmed solely from a heuristic or response difference.
- Never claim a hunt resumed at an exact checkpoint unless that checkpoint was actually restored.
