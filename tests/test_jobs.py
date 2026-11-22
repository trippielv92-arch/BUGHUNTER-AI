import pytest

from app.services.jobs import (
    create_job,
    create_hunt_job,
    transition_job,
    update_job_progress,
    recover_interrupted_jobs,
    list_jobs,
)
from app.services.projects import (
    create_project,
    add_scope_asset,
    approve_scope,
)


@pytest.fixture
def approved_project(db):
    project = create_project(db, "Job test project", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def test_create_job_requires_approved_scope(db):
    project = create_project(db, "Unapproved project")

    with pytest.raises(ValueError, match="approved"):
        create_job(db, project.id, "Test job")




def test_create_hunt_job_requires_approved_exact_https_target(
    db, approved_project
):
    job = create_hunt_job(
        db, approved_project.id, "https://example.com/", max_pages=25
    )

    assert job.job_type == "Automated hunt"
    assert job.status == "queued"
    assert job.progress == 0
    assert '"start_url": "https://example.com/"' in job.input_json
    assert '"max_pages": 25' in job.input_json

    with pytest.raises(ValueError, match="query parameters"):
        create_hunt_job(
            db,
            approved_project.id,
            "https://example.com/?token=do-not-store",
        )


def test_queued_hunt_can_be_stopped_before_worker_claims_it(
    db, approved_project
):
    job = create_hunt_job(
        db, approved_project.id, "https://example.com/"
    )

    stopped = transition_job(
        db, job.id, "stopped",
        checkpoint="Stopped before worker claim.",
    )

    assert stopped.status == "stopped"
    assert stopped.finished_at is not None

def test_job_lifecycle_and_terminal_state(db, approved_project):
    job = create_job(db, approved_project.id, "Test job")

    assert job.status == "queued"
    assert job.progress == 0

    transition_job(db, job.id, "running", progress=10)
    transition_job(db, job.id, "completed", progress=100)

    assert job.status == "completed"
    assert job.progress == 100
    assert job.started_at is not None
    assert job.finished_at is not None

    with pytest.raises(ValueError, match="Cannot transition"):
        transition_job(db, job.id, "running")


def test_job_rejects_invalid_progress(db, approved_project):
    job = create_job(db, approved_project.id, "Test job")

    with pytest.raises(ValueError, match="Progress"):
        transition_job(db, job.id, "running", progress=101)

    db.refresh(job)
    assert job.status == "queued"


def test_recovery_pauses_running_jobs_only(db, approved_project):
    running = create_job(db, approved_project.id, "Running job")
    queued = create_job(db, approved_project.id, "Queued job")

    transition_job(db, running.id, "running", progress=35)

    recovered = recover_interrupted_jobs(db)

    assert recovered == 1

    db.refresh(running)
    db.refresh(queued)

    assert running.status == "paused"
    assert running.progress == 35
    assert "Recovered after application restart." in running.checkpoint
    assert queued.status == "queued"


def test_paused_job_cannot_be_marked_running_without_resume_support(
    db, approved_project
):
    job = create_job(db, approved_project.id, "Recoverable job")

    transition_job(db, job.id, "running", progress=20)
    transition_job(db, job.id, "paused", progress=20)

    with pytest.raises(ValueError, match="Cannot transition"):
        transition_job(db, job.id, "running", progress=20)

    db.refresh(job)
    assert job.status == "paused"


def test_running_job_progress_is_persisted_without_status_transition(
    db, approved_project
):
    job = create_job(db, approved_project.id, "Progress job")
    transition_job(db, job.id, "running", progress=0)

    updated = update_job_progress(
        db, job.id, 35, checkpoint="Checked 5 of 15 pages"
    )

    assert updated.status == "running"
    assert updated.progress == 35
    assert updated.checkpoint == "Checked 5 of 15 pages"


def test_progress_update_rejects_non_running_jobs(db, approved_project):
    job = create_job(db, approved_project.id, "Queued job")

    with pytest.raises(ValueError, match="only be updated while"):
        update_job_progress(db, job.id, 10, checkpoint="Not started")


def test_progress_update_rejects_boolean_progress(db, approved_project):
    job = create_job(db, approved_project.id, "Boolean progress job")
    transition_job(db, job.id, "running", progress=0)

    with pytest.raises(ValueError, match="integer from 0 to 100"):
        update_job_progress(db, job.id, True)


def test_list_jobs_returns_project_jobs(db, approved_project):
    first = create_job(db, approved_project.id, "First job")
    second = create_job(db, approved_project.id, "Second job")

    jobs = list_jobs(db, approved_project.id)

    assert {job.id for job in jobs} == {first.id, second.id}
