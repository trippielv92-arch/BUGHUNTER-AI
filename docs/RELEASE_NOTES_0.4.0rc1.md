# BugHunter AI 0.4.0 Release Candidate 1

This candidate hardens the existing cloud-connected Parrot desktop architecture. It is not yet a production-ready final release: production API and persistent-worker deployment/runtime verification remain blocked by the Vercel Container Registry image quota described below.

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

- Python compilation: passed on current PR head `0731bc05045f9515e52e8b56b22a6c8e0565420d`.
- Full automated test suite: **187 passed, 3 warnings** in GitHub Actions on the current PR head.
- Python validation workflow: run [45453961257](https://github.com/trippielv92-arch/BUGHUNTER-AI/actions/runs/45453961257), passed.
- Debian build and package inspection workflow: run [45453961393](https://github.com/trippielv92-arch/BUGHUNTER-AI/actions/runs/45453961393), passed.
- Debian package: `bughunter-ai_0.4.0rc1_all.deb`, version `0.4.0rc1`, architecture `all`.
- GitHub Actions artifact: [BugHunter-AI-Parrot-DEB](https://github.com/trippielv92-arch/BUGHUNTER-AI/actions/runs/45453961393), artifact ID `14947594772`, available until 2026-12-24.
- SHA-256 of the uploaded **artifact ZIP** (not the inner .deb): `7d595cbf777968c1a2c4310d692dce5fcb47caada94d3f121aed91c55b6edf8`. A separate SHA-256 for the .deb itself was not emitted in the inspected CI log and is not asserted here.
- Package inspection confirmed the expected launcher/runtime files and no CI-generated `__pycache__`, `.pyc` or `.pyo` files.
- Production API/worker runtime smoke test: not verified.
- Parrot installation and desktop launch: not verified.

## Vercel deployment blocker

The latest production deployment failed while pushing the worker image to `daemon.hunt-worker`. The Vercel build log shows that the image built successfully, but the registry rejected the manifest because **the repository has reached the maximum allowed number of images**. This is an image-capacity/quota failure, not a Python build failure.

The project owner must inspect the repository's images in Vercel Container Registry and decide which obsolete images can safely be removed. Vercel documents these commands:

```bash
vercel vcr image ls daemon.hunt-worker --project bughunter-ai
vercel vcr image delete daemon.hunt-worker IMAGE_ID --project bughunter-ai
```

Image deletion is permanent. Do not delete the repository or any image until its tags and use are checked. After safely freeing capacity, retry the deployment and verify the API and worker startup.

## Supabase inspection — 2026-11-24

- Supabase project reports `ACTIVE_HEALTHY`.
- All 15 public application tables have RLS enabled.
- `anon` and `authenticated` have zero SELECT/INSERT privileges across those tables, consistent with the private API-only database architecture.
- No migration history is recorded. Do not add broad public RLS policies merely to silence the informational RLS-without-policy advisory.
- Four informational unindexed foreign-key notices were observed on `activities`, `findings`, `scan_checks` and `scope_assets`. They were not changed because this release does not require production DDL changes.
- API/worker startup against this exact live schema and verification of the intended private database connection still need to be completed.

## Release decision

Keep this as a release candidate. Do not remove the existing installation or label it stable until the production API and worker start successfully, account isolation is verified against the deployed environment, and the Parrot installation/desktop launch smoke test passes.
