import pytest
from sqlalchemy import select

from app.models.entities import Finding, Project, User
from app.services.projects import create_project


def test_project_and_child_reads_are_isolated_between_accounts(db):
    first_owner_id = db.info["owner_id"]
    first_project = create_project(db, "First account project")

    second_owner = User(
        username="second-account",
        password_hash="test-only-not-a-real-password-hash",
    )
    db.add(second_owner)
    db.commit()
    db.refresh(second_owner)

    db.info["owner_id"] = second_owner.id
    second_project = create_project(db, "Second account private project")
    db.add(Finding(
        project_id=second_project.id,
        title="Private second-account finding",
        category="Information Disclosure",
        asset="https://private.example.test/",
        evidence="private evidence",
    ))
    db.commit()

    db.info["owner_id"] = first_owner_id
    db.add(Finding(
        project_id=first_project.id,
        title="First account finding",
        category="Information Disclosure",
        asset="https://first.example.test/",
        evidence="first evidence",
    ))
    db.commit()

    # Clear the identity map so the test exercises database-level loader
    # criteria rather than returning objects already loaded by this session.
    db.expunge_all()

    projects = db.scalars(select(Project).order_by(Project.id)).all()
    findings = db.scalars(select(Finding).order_by(Finding.id)).all()

    assert [project.id for project in projects] == [first_project.id]
    assert [finding.title for finding in findings] == ["First account finding"]
    assert db.get(Project, second_project.id) is None


def test_account_cannot_insert_child_record_for_another_accounts_project(db):
    first_owner_id = db.info["owner_id"]
    first_project = create_project(db, "First account project")

    second_owner = User(
        username="second-account-write-test",
        password_hash="test-only-not-a-real-password-hash",
    )
    db.add(second_owner)
    db.commit()
    db.refresh(second_owner)

    db.info["owner_id"] = second_owner.id
    second_project = create_project(db, "Second account project")
    db.info["owner_id"] = first_owner_id

    db.add(Finding(
        project_id=second_project.id,
        title="Cross-tenant write attempt",
        category="Other",
        asset="https://example.test/",
    ))

    with pytest.raises(PermissionError, match="another account"):
        db.commit()

    db.rollback()
    db.expunge_all()
    assert db.get(Project, second_project.id) is None
