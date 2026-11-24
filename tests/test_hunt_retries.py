import json

from app.services.jobs import (
    create_hunt_job,
    retry_hunt_job,
    transition_job,
)


def test_transient_hunt_retries_are_bounded_and_secret_safe(db, approved_project):
    job = create_hunt_job(
        db, approved_project.id, "https://example.com/", max_pages=20
    )
    transition_job(db, job.id, "running", progress=37)

    first = retry_hunt_job(
        db, job.id, TimeoutError("Authorization: Bearer must-not-be-stored"),
        max_attempts=3,
    )
    db.refresh(job)
    assert first == 1
    assert job.status == "queued"
    assert job.progress == 0
    assert json.loads(job.input_json)["_retry_attempts"] == 1
    assert "must-not-be-stored" not in job.error_message
    assert "must-not-be-stored" not in job.checkpoint

    transition_job(db, job.id, "running", progress=12)
    second = retry_hunt_job(
        db, job.id, ConnectionError("private connection details"),
        max_attempts=3,
    )
    db.refresh(job)
    assert second == 2
    assert job.status == "queued"
    assert json.loads(job.input_json)["_retry_attempts"] == 2

    transition_job(db, job.id, "running", progress=8)
    exhausted = retry_hunt_job(
        db, job.id, TimeoutError("third failure"), max_attempts=3
    )
    db.refresh(job)
    assert exhausted == 0
    assert job.status == "running"


def test_retry_helper_does_not_requeue_non_hunt_or_non_running_jobs(
    db, approved_project
):
    ordinary = create_hunt_job(
        db, approved_project.id, "https://example.com/"
    )
    assert retry_hunt_job(db, ordinary.id, TimeoutError(), 3) == 0
    assert ordinary.status == "queued"

    transition_job(db, ordinary.id, "running")
    assert retry_hunt_job(db, ordinary.id, TimeoutError(), 1) == 0
    assert ordinary.status == "running"
