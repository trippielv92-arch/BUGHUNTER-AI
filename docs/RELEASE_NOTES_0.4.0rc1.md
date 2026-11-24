# BugHunter AI 0.4.0 Release Candidate 1

This candidate hardens the existing cloud-connected Parrot desktop architecture. It is not yet a production-ready final release: deployment/runtime verification remains blocked by the Vercel worker container registry permission issue described below.

## Included

- Persistent hunt job heartbeat updates using the existing `updated_at` field.
- Bounded retries (up to three total attempts) for transient HTTP transport, database operational, timeout and connection failures.
- Retry metadata stored in the existing job input JSON; no database schema migration is introduced.
- Exception details are not copied into persisted job error fields, reducing the chance of storing request headers, credentials or sensitive URLs.
- Exact finding deduplication now includes vulnerability category, preventing different vulnerability classes on the same asset from being collapsed.
- Additional endpoint-specific assessment recommendations for SQL injection resistance, reflected/DOM XSS, open redirects and SSRF URL inputs.
- Evidence SHA-256 tamper-detection regression coverage.
- Two-account project and child-record isolation regression coverage.
- Regression coverage for assessment planning, deduplication, worker heartbeat and retry limits.

## Security behavior

- Programme scope must still be explicitly reviewed and approved before a hunt is queued.
- Scope exclusions override inclusions.
- The new SQL injection, XSS, open-redirect and SSRF planner scenarios are **manual-only assessment guidance**. The planner makes zero network requests and executes zero payloads.
- Existing heuristic and passive observations remain potential leads. They are not automatically marked as confirmed vulnerabilities.
- Transient retries restart a hunt from the beginning. They do not claim to resume a crawler checkpoint.
- No schema migration or production data mutation is part of this candidate.

## Validation status

- Python compilation: passed.
- Source-code validation: compilation and the full automated test suite passed in GitHub Actions on commit `396bd6a` (185 tests passed).
- Debian package build: passed for that same source commit; the resulting artifact was inspected and is version `0.3.3`.
- The `0.4.0rc1` metadata bump and its new version assertion were added after that successful run. A new CI package build for the `0.4.0rc1` version has not yet been verified, so no `0.4.0rc1` installer is being published from that earlier artifact.
- Production API/worker runtime smoke test: not verified.
- Parrot installation and desktop launch: not verified.
- Vercel preview/production deployment: blocked because Vercel denied pushing the `daemon.hunt-worker` image to the project's Container Registry. The project owner must grant/create the registry repository in Vercel's Sandboxes → Container Registry settings, then redeploy.
- Supabase inspection: project healthy; all 15 public application tables have RLS enabled; `anon` and `authenticated` have zero SELECT/INSERT privileges across those tables. No migration history is recorded, so the API/worker startup path still needs live verification against the current schema.

## Release decision

Do not remove the existing installation or label this candidate stable until production API and worker startup, account isolation, and Parrot installation/launch have been verified.
