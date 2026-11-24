# BugHunter AI — product architecture

## One product

The Parrot desktop client is the only normal user-facing application. It talks to the central API over HTTPS. It does not own the production project database or run the production hunt worker.

## Runtime components

| Component | Responsibility | Source of truth |
|---|---|---|
| Parrot desktop | Sign-in, project setup, policy/scope review, hunt controls, findings review | None; client only |
| FastAPI | Authentication, tenant checks, policy/project APIs, durable job creation and result reads | PostgreSQL |
| Supabase PostgreSQL | Users, projects, scope, assets, jobs, findings, evidence | Canonical persistent state |
| Cloud daemon | Claims queued jobs, executes bounded discovery, writes progress/results | PostgreSQL |
| Debian package | Installs the desktop client and Python/Qt runtime | No production data |

## Normal hunt lifecycle

1. User signs in through the API.
2. User creates a project and imports/retrieves the official programme policy.
3. Policy analysis creates candidate assets and restrictions.
4. User reviews candidates and approves the exact included scope.
5. API validates the project and approved scope, then inserts a durable hunt job.
6. The worker claims the job, revalidates scope before network activity, and performs bounded discovery.
7. Assets, endpoints, observations, evidence and job progress are committed to PostgreSQL.
8. The desktop polls the API and renders the persisted state. Closing the desktop does not cancel the worker.

## Product boundaries

- Local SQLite is a developer-only mode, enabled explicitly with `BUGHUNTER_ENABLE_LOCAL_MODE=1`.
- The production desktop never connects directly to Supabase.
- The API and worker share the same PostgreSQL database; do not add a second cloud database or a second job queue.
- Evidence and state must not depend on the desktop filesystem or a Vercel function's ephemeral filesystem.
- The current worker performs bounded discovery and observation correlation. Vulnerability-specific verification remains a separate, explicit release milestone.

## Release acceptance

Do not call a release ready until all of these are demonstrated:
- `GET /health` returns healthy.
- An authorized account can log in and read its own projects.
- A project can be created and its exact approved scope persists.
- A harmless hunt job is durably queued and claimed by one worker.
- The worker records progress and a terminal result that the desktop can retrieve.
- A second account cannot read or mutate the first account's data.
- The Parrot Debian package installs, launches and signs in against the production API.
