"""Background worker for passive reconnaissance jobs."""
import json
import threading

from PySide6.QtCore import QThread, Signal

from app.database.db import SessionLocal
from app.services.jobs import transition_job, update_job_progress
from app.services.passive_recon import run_passive_recon


class PassiveReconWorker(QThread):
    progress = Signal(int, str)
    result_ready = Signal(dict)
    error_occurred = Signal(str)

    def __init__(
        self, job_id, project_id, *, use_certificate_transparency=True,
        delay_seconds=1.0, owner_id=None, parent=None
    ):
        super().__init__(parent)
        if not isinstance(owner_id, int) or owner_id <= 0:
            raise ValueError("An authenticated account is required for this worker.")
        self.owner_id = owner_id
        self.job_id = job_id
        self.project_id = project_id
        self.use_certificate_transparency = use_certificate_transparency
        self.delay_seconds = delay_seconds
        self._stop_event = threading.Event()
        self._finalization_lock = threading.Lock()
        self._finalizing = False

    def request_stop(self):
        with self._finalization_lock:
            if self._finalizing:
                return False
            self._stop_event.set()
            return True

    def run(self):
        db = SessionLocal()
        db.info["owner_id"] = self.owner_id
        try:
            transition_job(
                db, self.job_id, "running",
                checkpoint="Passive reconnaissance worker started.",
            )

            def report_progress(percent, message):
                try:
                    safe_percent = max(0, min(99, int(percent)))
                    update_job_progress(
                        db, self.job_id, safe_percent,
                        checkpoint=str(message)
                    )
                except Exception:
                    # Progress persistence must not abort reconnaissance.
                    db.rollback()

                try:
                    display_percent = max(0, min(100, int(percent)))
                except (TypeError, ValueError):
                    display_percent = 0

                self.progress.emit(display_percent, str(message))

            result = run_passive_recon(
                db,
                self.project_id,
                use_certificate_transparency=self.use_certificate_transparency,
                delay_seconds=self.delay_seconds,
                progress_callback=report_progress,
                stop_event=self._stop_event,
            )

            # Synchronize stop requests with final status persistence.
            with self._finalization_lock:
                self._finalizing = True
                if self._stop_event.is_set():
                    result["stopped"] = True

            result_json = json.dumps(
                result, ensure_ascii=False, default=str
            )

            if result.get("stopped"):
                transition_job(
                    db, self.job_id, "stopped",
                    checkpoint="Stopped safely after the current operation.",
                    result_summary=result_json,
                )
            else:
                transition_job(
                    db, self.job_id, "completed", progress=100,
                    checkpoint=(
                        f"Completed with warnings ({len(result.get('errors') or [])}). "
                        "Review the result summary for details."
                        if result.get("errors")
                        else "Passive reconnaissance finished."
                    ),
                    result_summary=result_json,
                )

            self.result_ready.emit(result)

        except Exception as exc:
            db.rollback()
            try:
                from app.models.entities import AssessmentJob
                job = db.get(AssessmentJob, self.job_id)
                if job and job.status in {"queued", "running"}:
                    transition_job(
                        db, self.job_id, "failed",
                        error_message=f"{type(exc).__name__}: {exc}",
                        checkpoint="Passive reconnaissance failed.",
                    )
            except Exception:
                db.rollback()

            self.error_occurred.emit(
                f"{type(exc).__name__}: {exc}"
            )
        finally:
            db.close()
