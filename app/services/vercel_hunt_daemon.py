"""Vercel daemon entrypoint using Supabase's persistent session pooler.

The API uses BUGHUNTER_DATABASE_URL (transaction pooler). The worker must
hold a PostgreSQL advisory lock across polling cycles, so it uses the separate
BUGHUNTER_WORKER_DATABASE_URL (session pooler).
"""
import os

worker_url = os.environ.get("BUGHUNTER_WORKER_DATABASE_URL", "").strip()
if not worker_url:
    raise RuntimeError(
        "BUGHUNTER_WORKER_DATABASE_URL must contain the Supabase session-pooler URL."
    )

os.environ["BUGHUNTER_DATABASE_URL"] = worker_url

from app.services.hunt_daemon import main  # noqa: E402


if __name__ == "__main__":
    main()
