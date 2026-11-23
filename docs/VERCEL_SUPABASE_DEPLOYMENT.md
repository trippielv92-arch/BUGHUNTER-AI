# Vercel + Supabase deployment

This deployment uses Vercel for the FastAPI serverless API, a Vercel Daemon
for the persistent hunt worker, and Supabase PostgreSQL for durable accounts,
projects, scope, jobs and findings. It does not require a VPS or custom domain.

## Before deploying

- Create a Supabase project and keep its database password private.
- Import this GitHub repository into Vercel as a new project, using the
  repository root as the project root.
- Deploy from the branch containing this configuration after it is merged
  into `main`.
- Confirm that Vercel Daemons are available for the project/account. Daemons
  are currently a beta feature and run only in production deployments.

The root `index.py` exposes the existing FastAPI application. The
`vercel.toml` starts exactly one persistent worker in `iad1`. Keep one
worker: the current worker uses a database advisory lock and is deliberately
a single-worker deployment until durable per-job leases and heartbeats exist.

## Supabase connection strings

In the Supabase dashboard, open **Connect** and copy both connection strings.
Use the same project and database for both:

1. **Transaction pooler** (port 6543) for the Vercel API. Set it as
   `BUGHUNTER_DATABASE_URL`. Change the URL scheme from
   `postgresql://` to `postgresql+psycopg://` if needed. The application
   disables local SQLAlchemy pooling and psycopg prepared statements for this
   transaction-mode connection.
2. **Session pooler** (port 5432) for the persistent worker. Set it as
   `BUGHUNTER_WORKER_DATABASE_URL`. This is important because the worker holds
   a PostgreSQL advisory lock on one connection while it polls the queue.

Keep the password URL-encoded if it contains reserved URL characters. Keep
the connection strings private.

## Vercel environment variables

In **Vercel → Project → Settings → Environment Variables**, add these variables
for **Production** (and Preview only if you intentionally want preview API
deployments connected to a separate test database):

| Variable | Value |
| --- | --- |
| `BUGHUNTER_DATABASE_URL` | Supabase transaction-pooler URL, port 6543, using `postgresql+psycopg://` |
| `BUGHUNTER_WORKER_DATABASE_URL` | Supabase session-pooler URL, port 5432, using `postgresql+psycopg://` |
| `BUGHUNTER_API_SECRET` | A unique random secret of at least 32 characters |
| `BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY` | A Fernet key generated locally; required before storing encrypted test-account credentials |

Generate the API secret locally with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Generate the credential encryption key locally with:

```bash
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Use the same API secret and Fernet key for every API/worker deployment that
accesses this database. Never commit them or send them in chat. If the
encryption key is lost, encrypted test-account credentials cannot be
decrypted.

After adding or changing environment variables, redeploy the production
deployment so both the API and daemon receive them.

## First deployment and account creation

1. Deploy the project from Vercel.
2. Open `https://YOUR-PROJECT.vercel.app/health`. Expect JSON with
   `"status": "ok"`. This first API startup initializes the PostgreSQL schema.
3. On your Parrot computer, activate the BugHunter AI virtual environment and
   set `BUGHUNTER_DATABASE_URL` temporarily to the **Supabase session-pooler**
   connection string (port 5432), converted to
   `postgresql+psycopg://`. Then create your account with the existing CLI:

   ```bash
   export BUGHUNTER_DATABASE_URL='postgresql+psycopg://...session-pooler...'
   .venv/bin/python -m app.cli create-account --username YOUR_USERNAME
   unset BUGHUNTER_DATABASE_URL
   ```

   The CLI prompts for the password twice; it is not placed in shell history.
   The session-pooler URL is used here because this is a one-off interactive
   administration task, not a serverless function.

4. Configure the desktop to use the Vercel API:

   ```bash
   export BUGHUNTER_API_URL='https://YOUR-PROJECT.vercel.app'
   python main.py
   ```

   Choose the central server login. Create a project in the remote workspace,
   review its policy-derived scope, and explicitly approve the exact included
   assets before queuing a cloud hunt.

## Important limitations

- The desktop remains a Parrot/Linux application. This deploys its API and
  worker, not a browser-based desktop UI.
- The worker is independent of the Parrot computer, but Vercel Daemons are a
  beta product with plan quotas and no persistent local filesystem. Durable
  application records live in Supabase PostgreSQL. Do not rely on daemon-local
  files for durable storage.
- Supabase Free has database/storage/egress limits and can pause an inactive
  project. Vercel Hobby is intended for personal, non-commercial use. Check
  the current limits in both dashboards before relying on the deployment.
- Daemons do not accept inbound HTTP traffic; the FastAPI function serves the
  public API. The worker polls PostgreSQL directly.
- Keep one daemon instance. Multi-worker lease/heartbeat recovery is not
  implemented.
- Cloud hosting does not expand authorization. Only explicitly approved
  programme assets may be tested. Current automated hunts remain bounded
  discovery and evidence correlation, not comprehensive vulnerability
  verification.
- This is an initial low-cost deployment, not a production SLA. Configure
  backups and monitor Vercel/Supabase usage. Supabase Free does not include
  automatic database backups.

Official guides:
- https://vercel.com/docs/frameworks/backend/fastapi
- https://vercel.com/daemons
- https://supabase.com/docs/guides/database/connecting-to-postgres
- https://supabase.com/docs/guides/database/connecting-to-postgres/pooling-and-limits
