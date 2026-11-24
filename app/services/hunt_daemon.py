"""Independent persistent worker for authorized BugHunter AI hunts."""
import json
import logging
import signal
from threading import Event, Thread
import fcntl

import httpx
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.core.config import DATA_DIR
from app.database.db import SessionLocal, engine, init_db
from app.models.entities import AssessmentJob, Project, ScanCheck
from app.services.jobs import (
    retry_hunt_job,
    touch_job_heartbeat,
    transition_job,
    update_job_progress,
)
from app.services.passive_recon import run_passive_recon
from app.services.engine import run_website_analysis
from app.services.validation import validate_project_findings
from app.services.program_intelligence import derive_policy_execution_controls

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
        with self.db.get_bind().connect() as connection:
            row = connection.execute(
                text(
                    "SELECT j.status AS job_status, "
                    "p.scope_approved AS scope_approved, "
                    "p.status AS project_status "
                    "FROM assessment_jobs j "
                    "JOIN projects p ON p.id=j.project_id "
                    "WHERE j.id=:id"
                ),
                {"id": self.job_id},
            ).first()
        return (
            row is None
            or row.job_status != "running"
            or not bool(row.scope_approved)
            or row.project_status == "deleted"
        )

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



class WorkerProcessLock:
    """Hold an exclusive process-wide lock for this database worker."""

    def __init__(self, connection=None, lock_file=None):
        self.connection = connection
        self.lock_file = lock_file

    def release(self):
        if self.connection is not None:
            try:
                self.connection.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": 731946205118},
                )
            finally:
                self.connection.close()
                self.connection = None
        if self.lock_file is not None:
            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                self.lock_file.close()
                self.lock_file = None


def acquire_worker_lock():
    """Ensure only one worker can recover or execute jobs for this database.

    PostgreSQL uses a session-level advisory lock held on a dedicated
    connection. SQLite uses an OS file lock in the configured data directory.
    This deliberately keeps the documented single-worker deployment model
    until durable per-job leases and heartbeats are implemented.
    """
    if engine.dialect.name == "postgresql":
        connection = engine.connect()
        try:
            acquired = connection.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": 731946205118},
            ).scalar_one()
            if not acquired:
                connection.close()
                return None
            return WorkerProcessLock(connection=connection)
        except Exception:
            connection.close()
            raise

    if engine.dialect.name == "sqlite":
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        lock_file = open(DATA_DIR / "hunt-worker.lock", "a+", encoding="utf-8")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_file.close()
            return None
        return WorkerProcessLock(lock_file=lock_file)

    raise RuntimeError("Hunt workers support SQLite and PostgreSQL only.")


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


def _job_heartbeat_loop(job_id, owner_id, stop_event):
    """Refresh updated_at independently while a bounded request is in flight."""
    while not stop_event.wait(20):
        heartbeat_db = SessionLocal()
        heartbeat_db.info["owner_id"] = owner_id
        try:
            if not touch_job_heartbeat(heartbeat_db, job_id):
                return
        except Exception:
            heartbeat_db.rollback()
            log.exception("Heartbeat update failed for hunt %s", job_id)
        finally:
            heartbeat_db.close()


def run_job(job_id, project_id, owner_id):
    db = SessionLocal()
    db.info["owner_id"] = owner_id
    heartbeat_stop = Event()
    heartbeat_thread = None

    try:
        job = db.get(AssessmentJob, job_id)
        if not job or job.project_id != project_id or job.status != "running":
            return
        heartbeat_thread = Thread(
            target=_job_heartbeat_loop,
            args=(job_id, owner_id, heartbeat_stop),
            name=f"bughunter-heartbeat-{job_id}",
            daemon=True,
        )
        heartbeat_thread.start()
        job_stop = JobStopSignal(db, job_id)

        project = db.get(Project, project_id)
        if not project or project.status == "deleted" or not project.scope_approved:
            raise ValueError("Project unavailable or approved scope revoked.")

        config = json.loads(job.input_json or "{}")
        target = config.get("start_url")
        max_pages = config.get("max_pages", 100)

        if not isinstance(target, str):
            raise ValueError("Hunt target is missing.")
        if not isinstance(max_pages, int) or not 1 <= max_pages <= 100:
            raise ValueError("Invalid hunt page limit.")

        log.info("Claimed hunt %s for project %s", job_id, project_id)

        policy_controls = derive_policy_execution_controls(
            project.policy_text or ""
        )
        results = {
            "policy_controls": policy_controls,
            "passive_recon": None,
            "website_analysis": None,
            "validation": None,
        }

        # Phase 1: DNS and certificate-transparency discovery.
        if (
            config.get("passive_recon", True)
            and policy_controls["passive_discovery_allowed"]
        ):
            results["passive_recon"] = run_passive_recon(
                db, project_id,
                use_certificate_transparency=bool(
                    config.get("certificate_transparency", True)
                ),
                delay_seconds=policy_controls["minimum_request_delay_seconds"],
                stop_event=job_stop,
                progress_callback=lambda pct, msg: persist_progress(
                    db, job_id, int(int(pct) * 0.20),
                    "Passive discovery: " + str(msg),
                ),
            )
        elif config.get("passive_recon", True):
            results["passive_recon"] = {
                "skipped": True,
                "reason": (
                    "Passive discovery was skipped because the programme policy "
                    "explicitly prohibits automated tools."
                ),
                "policy_evidence": policy_controls[
                    "passive_discovery_prohibition_evidence"
                ],
                "network_requests": 0,
            }

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

        # Phase 2: enforce explicit programme restrictions before active requests.
        if not policy_controls["active_automated_testing_allowed"]:
            reason = (
                "Active automated crawling was skipped because the supplied "
                "programme policy explicitly prohibits automated scanning/testing."
            )
            results["website_analysis"] = {
                "skipped": True,
                "reason": reason,
                "policy_evidence": policy_controls[
                    "automated_testing_prohibition_evidence"
                ],
                "network_requests": 0,
                "payloads_executed": 0,
            }
            db.add(ScanCheck(
                project_id=project_id,
                asset=target,
                check_name="Programme policy execution guard",
                outcome="skipped",
                details=json.dumps(results["website_analysis"], ensure_ascii=False),
            ))
            db.commit()
            persist_progress(
                db, job_id, 90,
                "Active discovery skipped to comply with programme policy.",
            )
        else:
            # The strictest parsed programme rate limit overrides our default delay.
            credential_profiles = []
            try:
                from urllib.parse import urlsplit
                from app.services.credential_vault import (
                    load_test_credential_profiles,
                )
                credential_profiles = load_test_credential_profiles(
                    db, project_id, urlsplit(target).hostname
                )
                results["credentialed_assessment"] = {
                    "status": (
                        "configured" if credential_profiles else "not_configured"
                    ),
                    "profiles_available": len(credential_profiles),
                    "secret_material_in_job_input": False,
                }
            except RuntimeError as credential_error:
                results["credentialed_assessment"] = {
                    "status": "skipped",
                    "reason": str(credential_error),
                    "network_requests": 0,
                    "secret_material_in_job_input": False,
                }
                db.add(ScanCheck(
                    project_id=project_id,
                    asset=target,
                    check_name="Credentialed assessment configuration",
                    outcome="skipped",
                    details=str(credential_error)[:1000],
                ))
                db.commit()

            results["website_analysis"] = run_website_analysis(
                db, project_id, target,
                max_pages=max_pages,
                delay_seconds=policy_controls[
                    "minimum_request_delay_seconds"
                ],
                stop_event=job_stop,
                progress_callback=lambda pct, msg: persist_progress(
                    db, job_id, 20 + int(int(pct) * 0.75),
                    "Website discovery: " + str(msg),
                ),
                auth_profiles=credential_profiles,
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
            retryable = isinstance(
                exc,
                (
                    httpx.TransportError,
                    OperationalError,
                    TimeoutError,
                    ConnectionError,
                ),
            )
            if job and job.status == "running" and retryable:
                retry_number = retry_hunt_job(
                    db, job_id, exc, max_attempts=3
                )
                if retry_number:
                    delay = min(2 ** retry_number, 10)
                    log.warning(
                        "Queued transient retry %s for hunt %s; "
                        "waiting %s seconds before another claim.",
                        retry_number, job_id, delay,
                    )
                    STOP.wait(delay)
                    return

            job = db.get(AssessmentJob, job_id)
            if job and job.status in {"queued", "running"}:
                # Do not persist exception text: it may contain secrets,
                # request headers, or sensitive URL query parameters.
                transition_job(
                    db, job_id, "failed",
                    error_message=(
                        f"{type(exc).__name__}: automatic retries exhausted "
                        "or this failure is not retryable."
                    ),
                    checkpoint=(
                        "Background hunt failed. Review the failure type "
                        "and explicitly start a new hunt after resolving it."
                    ),
                )
        except Exception:
            db.rollback()
            log.exception("Could not persist failure state for job %s", job_id)
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=2)
        db.close()


def main():
    if engine.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("Hunt workers require SQLite or PostgreSQL.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    worker_lock = acquire_worker_lock()
    if worker_lock is None:
        log.warning(
            "Another BugHunter worker already owns this database; "
            "this worker instance will exit without recovering or claiming jobs."
        )
        return

    try:
        init_db()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        # Recovery is safe only while holding the exclusive worker lock:
        # no other worker can own a live running job at this point.
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
    finally:
        worker_lock.release()


if __name__ == "__main__":
    main()
