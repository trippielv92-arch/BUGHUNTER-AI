from datetime import datetime, timezone
import json

from sqlalchemy import select

from app.models.entities import AssessmentJob, Project
from app.services.projects import log_activity


VALID_STATUSES = {
    "queued", "running", "paused",
    "stopped", "completed", "failed"
}

ALLOWED_TRANSITIONS = {
    "queued": {"running", "stopped", "failed"},
    "running": {"paused", "stopped", "completed", "failed"},
    # Paused jobs cannot resume until crawler checkpoints are implemented.
    "paused": {"stopped", "failed"},
    "stopped": set(),
    "completed": set(),
    "failed": set(),
}


def utc_now():
    return datetime.now(timezone.utc)


def create_job(db, project_id, job_type):
    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found.")
    if project.status == "deleted":
        raise ValueError("Cannot create a job for a retired project.")
    if not project.scope_approved:
        raise ValueError("Project scope must be approved first.")
    if not isinstance(job_type, str) or not job_type.strip():
        raise ValueError("Job type is required.")

    job = AssessmentJob(
        project_id=project_id,
        job_type=job_type.strip()[:100],
        status="queued",
        progress=0,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    log_activity(
        db, project_id, "Assessment job created",
        f"Job #{job.id}: {job.job_type}"
    )
    return job




def create_hunt_job(db, project_id, start_url, max_pages=15):
    """Queue one authorized hunt for the independent background service."""
    from app.services.workflows import validate_target

    project = db.get(Project, project_id)
    if not project or project.status == "deleted":
        raise ValueError("Project not found or retired.")
    if not project.scope_approved:
        raise ValueError("Approve the project's scope before starting a hunt.")
    if not isinstance(start_url, str) or not start_url.strip():
        raise ValueError("An HTTPS target URL is required.")
    if (not isinstance(max_pages, int) or isinstance(max_pages, bool)
            or not 1 <= max_pages <= 25):
        raise ValueError("Page limit must be between 1 and 25.")

    parsed = validate_target(db, project_id, start_url.strip())
    if parsed.scheme.lower() != "https" or parsed.port not in (None, 443):
        raise ValueError("Hunts require an approved HTTPS target on port 443.")

    job = AssessmentJob(
        project_id=project_id,
        job_type="Automated hunt",
        status="queued",
        progress=0,
        checkpoint="Queued for the independent background hunt service.",
        input_json=json.dumps({
            "start_url": start_url.strip(),
            "max_pages": max_pages,
            "passive_recon": True,
            "certificate_transparency": True,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    log_activity(
        db, project_id, "Automated hunt queued",
        f"Job #{job.id}: target {start_url.strip()}"
    )
    return job


def transition_job(
    db, job_id, new_status, progress=None,
    checkpoint=None, result_summary=None, error_message=None
):
    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid job status.")

    job = db.get(AssessmentJob, job_id)
    if not job:
        raise ValueError("Job not found.")

    if new_status not in ALLOWED_TRANSITIONS[job.status]:
        raise ValueError(
            f"Cannot transition job from {job.status} to {new_status}."
        )

    if progress is not None:
        if (
            not isinstance(progress, int)
            or isinstance(progress, bool)
            or not 0 <= progress <= 100
        ):
            raise ValueError("Progress must be an integer from 0 to 100.")
        job.progress = progress

    if checkpoint is not None:
        job.checkpoint = checkpoint[:20000]
    if result_summary is not None:
        job.result_summary = result_summary[:20000]
    if error_message is not None:
        job.error_message = error_message[:10000]

    job.status = new_status
    job.updated_at = utc_now()

    if new_status == "running" and job.started_at is None:
        job.started_at = utc_now()

    if new_status in {"stopped", "completed", "failed"}:
        job.finished_at = utc_now()

    db.commit()
    db.refresh(job)

    log_activity(
        db, job.project_id, "Assessment job updated",
        f"Job #{job.id}: {new_status} ({job.progress}%)"
    )
    return job



def update_job_progress(db, job_id, progress, checkpoint=None):
    """Persist progress for an active job without changing its status."""
    if (
        not isinstance(progress, int)
        or isinstance(progress, bool)
        or not 0 <= progress <= 100
    ):
        raise ValueError("Progress must be an integer from 0 to 100.")

    job = db.get(AssessmentJob, job_id)
    if not job:
        raise ValueError("Job not found.")
    if job.status != "running":
        raise ValueError("Progress can only be updated while a job is running.")

    job.progress = progress
    if checkpoint is not None:
        job.checkpoint = str(checkpoint)[:20000]
    job.updated_at = utc_now()

    db.commit()
    return job


def list_jobs(db, project_id):
    return db.scalars(
        select(AssessmentJob)
        .where(AssessmentJob.project_id == project_id)
        .order_by(AssessmentJob.created_at.desc())
    ).all()


def recover_interrupted_jobs(db):
    jobs = db.scalars(
        select(AssessmentJob).where(
            AssessmentJob.status == "running",
            AssessmentJob.job_type != "Automated hunt",
        )
    ).all()

    for job in jobs:
        job.status = "paused"
        job.updated_at = utc_now()
        job.checkpoint = (
            job.checkpoint + "\nRecovered after application restart."
        )[-20000:]

    if jobs:
        db.commit()

    return len(jobs)
