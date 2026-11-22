# Cloud deployment (VPS / Docker Compose)

BugHunter AI can use the existing Parrot desktop as a client while a separate
cloud worker processes durable hunt jobs. The API and worker share PostgreSQL;
the worker does not depend on the desktop or its SQLite database.

## What this deployment provides

- PostgreSQL-backed accounts, projects, scope, policy snapshots, jobs and findings.
- An authenticated API for the existing desktop remote-workspace mode.
- A persistent worker that claims queued hunts using PostgreSQL row locks and
  SKIP LOCKED to make each individual claim atomic. Run one worker instance
  with this initial deployment; multi-worker lease/heartbeat recovery is not
  implemented yet.
- Restart recovery: interrupted hunts are safely requeued from the beginning.
- Persistent Docker volumes for the database and evidence/data directory.

This is a deployment foundation, not a hosted service that is already running.
You must provide a VPS/cloud host, domain, TLS reverse proxy and backups.

## Deploy

1. Install Docker Engine and the Docker Compose plugin on a Linux VPS.
2. Clone this repository on the VPS.
3. Copy .env.cloud.example to .env.
4. Set unique, long random values for POSTGRES_PASSWORD and
   BUGHUNTER_API_SECRET (at least 32 characters for the API secret).
5. Ensure the password embedded in BUGHUNTER_DATABASE_URL exactly matches
   POSTGRES_PASSWORD. URL-encode special characters in the password.
6. Start the stack:

   docker compose --env-file .env -f docker-compose.cloud.yml up -d --build

7. Check service health and logs:

   docker compose --env-file .env -f docker-compose.cloud.yml ps
   docker compose --env-file .env -f docker-compose.cloud.yml logs -f api worker

8. Create the first account interactively (the password is prompted, not placed
   in shell history):

   docker compose --env-file .env -f docker-compose.cloud.yml exec api python -m app.cli create-account --username YOUR_USERNAME

The API binds to 127.0.0.1:8765 on the host, not to every public interface.
Put it behind a TLS reverse proxy (for example Caddy or Nginx), expose HTTPS
only, and set the desktop BUGHUNTER_API_URL to the resulting HTTPS URL.
Do not expose port 8765 directly to the public internet.

## Desktop connection

On Parrot, configure the desktop environment before launching the app:

   export BUGHUNTER_API_URL="https://YOUR_API_DOMAIN"
   python main.py

Select Connect to central BugHunter AI server on the login screen.
Create projects in the remote workspace. The remote API and cloud worker share
the same database, so closing or shutting down the Parrot computer does not
stop a hunt already queued on the server.

The existing local SQLite workspace and systemd worker remain available as a
separate local mode. A local project is not automatically synchronized with
the cloud workspace; create or manage it in the selected workspace.

## Private programmes

For programmes that require login or cannot be retrieved by the server,
use the programme policy text import/paste field in the policy analysis screen.
This avoids collecting or storing provider passwords and session cookies.
Only the official policy text should be imported. Authenticated browser-session
capture is not part of this deployment foundation.

## Important current limitations

- Cloud deployment does not make the current discovery engine a comprehensive
  vulnerability verifier. Existing automated hunts still perform passive
  DNS/Certificate Transparency discovery, bounded same-host HTTPS GET
  discovery, endpoint inventory and evidence correlation.
- Vulnerability-specific checks requiring authentication, controlled accounts,
  payloads or special permission are not silently run. Potential findings are
  not automatically promoted to confirmed.
- Policy extraction is generic across programme URLs and recognizes
  several common providers. It preserves page section boundaries, extracts
  exact hostnames, wildcard hostnames, CIDRs, IP literals and path-limited
  URLs, and records policy restrictions as evidence. Provider recognition
  does not mean a provider-specific API adapter is available.
- Only clear, exact-host inclusion candidates can be bulk-proposed to scope.
  Wildcards, CIDRs, IPs and URL/path candidates are not expanded into broader
  hostname authorization. The complete proposed list still requires explicit
  scope approval. A changed policy snapshot revokes previous scope approval.
- Explicit automated-scanning prohibitions suppress active website crawling.
  A broader ban on automated tools also suppresses passive discovery. Parsed
  request-rate limits increase the delay between active requests. These
  controls are conservative heuristics; inspect the original policy.
- A policy page that is JavaScript-rendered, blocked, or behind authentication
  may require manual policy text import. Authenticated browser capture is not
  included yet.
- Configure encrypted backups for PostgreSQL and the persistent data volume.
  The application database/evidence volume is not encrypted at rest by this
  Compose file.
- This Compose stack is a single-host deployment. For production multi-region
  operation, add managed PostgreSQL, object storage, monitoring, secrets
  management, automated backups and a hardened TLS ingress.

Never scan assets unless the official programme policy authorizes the activity.
