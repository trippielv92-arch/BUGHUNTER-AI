import json
import time
from threading import Event, Lock

from PySide6.QtCore import QThread, Signal

from app.database.db import SessionLocal
from app.services.engine import run_website_analysis
from app.services.jobs import transition_job, update_job_progress
from app.services.validation import validate_project_findings


class WebsiteAnalysisWorker(QThread):
    progress = Signal(int, str)
    result_ready = Signal(dict)
    error_occurred = Signal(str)

    def __init__(
        self,
        job_id,
        project_id,
        start_url,
        max_pages=15,
        delay_seconds=0.75,
        owner_id=None,
        parent=None,
    ):
        super().__init__(parent)
        if not isinstance(owner_id, int) or owner_id <= 0:
            raise ValueError("An authenticated account is required for this worker.")
        self.owner_id = owner_id
        self.job_id = job_id
        self.project_id = project_id
        self.start_url = start_url
        self.max_pages = max_pages
        self.delay_seconds = delay_seconds
        self.stop_event = Event()
        self._finalization_lock = Lock()
        self._finalizing = False

    def request_stop(self):
        with self._finalization_lock:
            if self._finalizing:
                return False
            self.stop_event.set()
            return True

    def run(self):
        db = SessionLocal()
        db.info["owner_id"] = self.owner_id

        try:
            transition_job(
                db,
                self.job_id,
                "running",
                progress=0,
                checkpoint="Website analysis started.",
            )

            last_persisted_percent = None
            last_persisted_at = 0.0

            def handle_progress(percent, message):
                nonlocal last_persisted_percent, last_persisted_at

                now = time.monotonic()
                should_persist = (
                    last_persisted_percent != percent
                    or now - last_persisted_at >= 2.0
                )

                if should_persist:
                    try:
                        update_job_progress(
                            db,
                            self.job_id,
                            min(94, max(0, int(percent))),
                            checkpoint=message,
                        )
                        last_persisted_percent = percent
                        last_persisted_at = now
                    except Exception:
                        # Persistence failure must not interrupt the assessment.
                        db.rollback()

                self.progress.emit(percent, message)

            stats = run_website_analysis(
                db,
                self.project_id,
                self.start_url,
                max_pages=self.max_pages,
                delay_seconds=self.delay_seconds,
                stop_event=self.stop_event,
                progress_callback=handle_progress,
            )

            # Validate existing passive observations without making
            # additional network requests or executing test payloads.
            if stats.get("stopped") or self.stop_event.is_set():
                stats["validation"] = {
                    "skipped": True,
                    "reason": "Scan was stopped before validation.",
                }
            else:
                self.progress.emit(
                    95,
                    "Correlating passive evidence with potential findings...",
                )
                try:
                    stats["validation"] = validate_project_findings(
                        db, self.project_id
                    )
                except Exception as validation_exc:
                    db.rollback()
                    stats["validation"] = {
                        "error": type(validation_exc).__name__,
                        "message": "Validation could not be completed. "
                                   "The scan results were retained.",
                    }

            # Aggregate the actual discovered attack surface, existing
            # assessment tasks, coverage, findings and duplicate-review data.
            # This service is read-only and performs no network requests.
            try:
                from app.services.project_intelligence import (
                    get_project_intelligence,
                )

                stats["project_intelligence"] = get_project_intelligence(
                    db,
                    self.project_id,
                )
            except Exception as intelligence_exc:
                db.rollback()
                stats["project_intelligence"] = {
                    "error": type(intelligence_exc).__name__,
                    "message": (
                        "Project intelligence could not be assembled. "
                        "The website analysis results were retained."
                    ),
                }

            # Establish a clear boundary between accepting a stop request
            # and committing the final job state.
            with self._finalization_lock:
                self._finalizing = True
                stop_requested = self.stop_event.is_set()

            if stop_requested:
                stats["stopped"] = True

            summary = json.dumps(stats, indent=2)

            if stats.get("stopped"):
                transition_job(
                    db,
                    self.job_id,
                    "stopped",
                    progress=min(
                        99,
                        int(
                            stats["requests_attempted"]
                            * 100
                            / self.max_pages
                        ),
                    ),
                    checkpoint=summary,
                    result_summary=summary,
                )
            else:
                transition_job(
                    db,
                    self.job_id,
                    "completed",
                    progress=100,
                    checkpoint=summary,
                    result_summary=summary,
                )

            self.result_ready.emit(stats)

        except Exception as exc:
            db.rollback()

            try:
                from app.models.entities import AssessmentJob

                job = db.get(AssessmentJob, self.job_id)

                if job and job.status in {"queued", "running"}:
                    transition_job(
                        db,
                        self.job_id,
                        "failed",
                        error_message=str(exc),
                        checkpoint="Website analysis failed.",
                    )
            except Exception:
                db.rollback()

            self.error_occurred.emit(str(exc))

        finally:
            db.close()
