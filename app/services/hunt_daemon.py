"""Independent persistent worker for authorized BugHunter AI hunts."""
import json
import logging
import signal
from threading import Event

from sqlalchemy import text

from app.core.config import DATA_DIR
from app.database.db import SessionLocal, engine, init_db
from app.models.entities import AssessmentJob, Project
from app.services.jobs import transition_job, update_job_progress
from app.services.passive_recon import run_passive_recon
from app.services.engine import run_website_analysis
from app.services.validation import validate_project_findings

JOB_TYPE = "Automated hunt"
POLL_SECONDS = 2
STOP = Event()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("bughunter.worker")


class JobStopSignal:
    """Combine process shutdown with a durable per-job stop request."""

    def __init__(self, db, job_id):
        self.db = db
        self.job_id = job_id

    def is_set(self):
        if STOP.is_set():
            return True
        # Use a fresh connection so a long-lived ORM transaction cannot
        # retain a stale SQLite read snapshot after the UI commits a stop.
        with engine.connect() as connection:
            status = connection.execute(
                text("SELECT status FROM assessment_jobs WHERE id=:id"),
                {"id": self.job_id},
            ).scalar_one_or_none()
        return status != "running"

    def wait(self, seconds):
        import time
        deadline = time.monotonic() + max(0.0, float(seconds))
        while True:
            if self.is_set():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self.is_set()
            STOP.wait(min(0.25, remaining))


def shutdown(signum, frame):
    log.info("Shutdown requested; stopping active hunt safely.")
    STOP.set()


def recover_interrupted_hunts():
    """Restart interrupted hunts from the beginning, never fake resume."""
    with engine.begin() as connection:
        rows = connection.execute(text(
            "SELECT id FROM assessment_jobs "
            "WHERE status='running' AND job_type=:kind"
        ), {"kind": JOB_TYPE}).fetchall()

        for row in rows:
            connection.execute(text(
                "UPDATE assessment_jobs SET status='queued', progress=0, "
                "updated_at=CURRENT_TIMESTAMP, finished_at=NULL, "
                "checkpoint=substr(coalesce(checkpoint,'') || "
                "' Worker restarted: safely restarting this hunt from the "
                "beginning because mid-crawl resume is not yet supported.', "
                "1, 20000) WHERE id=:id AND status='running'"
            ), {"id": row[0]})

    if rows:
        log.warning("Requeued %s interrupted hunt(s).", len(rows))


def claim_next_job():
    """Atomically claim one queued hunt on SQLite or PostgreSQL."""
    with engine.connect() as connection:
        try:
            if engine.dialect.name == "sqlite":
                # SQLite has no row-level SKIP LOCKED; serialize claimers.
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                row = connection.execute(text(
                    "SELECT j.id, j.project_id, p.owner_id "
                    "FROM assessment_jobs j "
                    "JOIN projects p ON p.id=j.project_id "
                    "WHERE j.status='queued' AND j.job_type=:kind "
                    "AND p.status <> 'deleted' AND p.scope_approved IS TRUE "
                    "AND p.owner_id IS NOT NULL "
                    "ORDER BY j.created_at, j.id LIMIT 1"
                ), {"kind": JOB_TYPE}).first()
            elif engine.dialect.name == "postgresql":
                # Multiple cloud workers can safely claim different jobs.
                connection.begin()
                row = connection.execute(text(
                    "SELECT j.id, j.project_id, p.owner_id "
                    "FROM assessment_jobs j "
                    "JOIN projects p ON p.id=j.project_id "
                    "WHERE j.status='queued' AND j.job_type=:kind "
                    "AND p.status <> 'deleted' AND p.scope_approved IS TRUE "
                    "AND p.owner_id IS NOT NULL "
                    "ORDER BY j.created_at, j.id LIMIT 1 "
                    "FOR UPDATE OF j SKIP LOCKED"
                ), {"kind": JOB_TYPE}).first()
            else:
                raise RuntimeError(
                    "Hunt workers support SQLite and PostgreSQL only."
                )

            if not row:
                connection.commit()
                return None

            result = connection.execute(text(
                "UPDATE assessment_jobs "
                "SET status='running', progress=0, "
                "started_at=COALESCE(started_at, CURRENT_TIMESTAMP), "
                "updated_at=CURRENT_TIMESTAMP, "
                "checkpoint='Atomically claimed by persistent worker.' "
                "WHERE id=:id AND status='queued'"
            ), {"id": row[0]})

            if result.rowcount != 1:
                connection.rollback()
                return None

            connection.commit()
            return tuple(row)
        except Exception:
            connection.rollback()
            raise


def persist_progress(db, job_id, percent, message):
    try:
        status = db.execute(
            text("SELECT status FROM assessment_jobs WHERE id=:id"),
            {"id": job_id},
        ).scalar_one_or_none()
        if status != "running":
            return
        update_job_progress(
            db, job_id, max(0, min(99, int(percent))),
            checkpoint=str(message)[:20000],
        )
    except Exception:
        db.rollback()
        log.exception("Progress persistence failed for job %s", job_id)


def run_job(job_id, project_id, owner_id):
    db = SessionLocal()
    db.info["owner_id"] = owner_id

    try:
        job = db.get(AssessmentJob, job_id)
        if not job or job.project_id != project_id or job.status != "running":
            return
        job_stop = JobStopSignal(db, job_id)

        project = db.get(Project, project_id)
        if not project or project.status == "deleted" or not project.scope_approved:
            raise ValueError("Project unavailable or approved scope revoked.")

        config = json.loads(job.input_json or "{}")
        target = config.get("start_url")
        max_pages = config.get("max_pages", 15)

        if not isinstance(target, str):
            raise ValueError("Hunt target is missing.")
        if not isinstance(max_pages, int) or not 1 <= max_pages <= 25:
            raise ValueError("Invalid hunt page limit.")

        log.info("Claimed hunt %s for project %s", job_id, project_id)

        results = {"passive_recon": None, "website_analysis": None,
                   "validation": None}

        # Phase 1: DNS and certificate-transparency discovery.
        if config.get("passive_recon", True):
            results["passive_recon"] = run_passive_recon(
                db, project_id,
                use_certificate_transparency=bool(
                    config.get("certificate_transparency", True)
                ),
                delay_seconds=1.0,
                stop_event=job_stop,
                progress_callback=lambda pct, msg: persist_progress(
                    db, job_id, int(int(pct) * 0.20),
                    "Passive discovery: " + str(msg),
                ),
            )

        if job_stop.is_set() or (results["passive_recon"] or {}).get("stopped"):
            current = db.execute(
                text("SELECT status FROM assessment_jobs WHERE id=:id"),
                {"id": job_id},
            ).scalar_one_or_none()
            if current == "running":
                transition_job(
                    db, job_id, "stopped",
                    progress=min(99, job.progress),
                    checkpoint="Hunt stopped safely during passive discovery.",
                    result_summary=json.dumps(results, default=str)[:20000],
                )
            return

        # Recheck scope before active website retrieval.
        db.expire_all()
        project = db.get(Project, project_id)
        if not project or project.status == "deleted" or not project.scope_approved:
            raise ValueError("Approved scope changed before website analysis.")

        # Phase 2: bounded, same-host, HTTPS GET-only website discovery.
        results["website_analysis"] = run_website_analysis(
            db, project_id, target,
            max_pages=max_pages,
            delay_seconds=0.75,
            stop_event=job_stop,
            progress_callback=lambda pct, msg: persist_progress(
                db, job_id, 20 + int(int(pct) * 0.75),
                "Website discovery: " + str(msg),
            ),
        )

        if job_stop.is_set() or (results["website_analysis"] or {}).get("stopped"):
            current = db.execute(
                text("SELECT status FROM assessment_jobs WHERE id=:id"),
                {"id": job_id},
            ).scalar_one_or_none()
            if current == "running":
                transition_job(
                    db, job_id, "stopped",
                    progress=min(99, job.progress),
                    checkpoint="Hunt stopped safely after the current operation.",
                    result_summary=json.dumps(results, default=str)[:20000],
                )
            return

        # Evidence correlation only: no additional requests or payloads.
        try:
            results["validation"] = validate_project_findings(db, project_id)
        except Exception as exc:
            db.rollback()
            results["validation"] = {
                "error": type(exc).__name__,
                "message": "Evidence correlation failed; discovery records were retained.",
            }

        transition_job(
            db, job_id, "completed", progress=100,
            checkpoint="Discovery and evidence correlation completed.",
            result_summary=json.dumps(
                results, ensure_ascii=False, default=str
            )[:20000],
        )
        log.info("Completed hunt %s", job_id)

    except Exception as exc:
        db.rollback()
        log.exception("Hunt %s failed", job_id)
        try:
            job = db.get(AssessmentJob, job_id)
            if job and job.status in {"queued", "running"}:
                transition_job(
                    db, job_id, "failed",
                    error_message=f"{type(exc).__name__}: {str(exc)[:1500]}",
                    checkpoint="Background hunt failed; inspect the error before retrying.",
                )
        except Exception:
            db.rollback()
            log.exception("Could not persist failure state for job %s", job_id)
    finally:
        db.close()


def main():
    if engine.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("Hunt workers require SQLite or PostgreSQL.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    recover_interrupted_hunts()

    log.info("Persistent worker started using database %s", engine.url.database)

    while not STOP.is_set():
        try:
            item = claim_next_job()
            if item:
                run_job(int(item[0]), int(item[1]), int(item[2]))
                continue
        except Exception:
            log.exception("Worker queue loop error")
        STOP.wait(POLL_SECONDS)

    log.info("Persistent worker stopped.")


if __name__ == "__main__":
    main()
