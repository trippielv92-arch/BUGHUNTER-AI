import pytest
from sqlalchemy import select

from app.models.entities import Finding, Project, User
from app.services.projects import create_project


def test_project_and_child_reads_are_isolated_between_accounts(db):
    first_owner_id = db.info["owner_id"]
    first_project = create_project(db, "First account project")
    first_project_id = first_project.id

    second_owner = User(
        username="second-account",
        password_hash="test-only-not-a-real-password-hash",
    )
    db.add(second_owner)
    db.commit()
    db.refresh(second_owner)

    db.info["owner_id"] = second_owner.id
    second_project = create_project(db, "Second account private project")
    second_project_id = second_project.id
    db.add(Finding(
        project_id=second_project_id,
        title="Private second-account finding",
        category="Information Disclosure",
        asset="https://private.example.test/",
        evidence="private evidence",
    ))
    db.commit()

    db.info["owner_id"] = first_owner_id
    db.add(Finding(
        project_id=first_project_id,
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

    assert [project.id for project in projects] == [first_project_id]
    assert [finding.title for finding in findings] == ["First account finding"]
    assert db.get(Project, second_project_id) is None


def test_account_cannot_insert_child_record_for_another_accounts_project(db):
    first_owner_id = db.info["owner_id"]
    first_project = create_project(db, "First account project")
    first_project_id = first_project.id

    second_owner = User(
        username="second-account-write-test",
        password_hash="test-only-not-a-real-password-hash",
    )
    db.add(second_owner)
    db.commit()
    db.refresh(second_owner)

    db.info["owner_id"] = second_owner.id
    second_project = create_project(db, "Second account project")
    second_project_id = second_project.id
    db.info["owner_id"] = first_owner_id

    db.add(Finding(
        project_id=second_project_id,
        title="Cross-tenant write attempt",
        category="Other",
        asset="https://example.test/",
    ))

    with pytest.raises(PermissionError, match="another account"):
        db.commit()

    db.rollback()
    db.expunge_all()
    assert db.get(Project, second_project_id) is None


def test_authenticated_api_hides_projects_from_other_accounts(db, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session as ORMSession

    from app.api import server
    from app.services.auth import create_owner

    monkeypatch.setenv(
        "BUGHUNTER_API_SECRET",
        "test-only-api-secret-with-at-least-32-characters",
    )
    first_owner_id = db.info["owner_id"]
    second_owner = create_owner(
        db,
        "second-api-owner",
        "second-api-owner-password-456",
    )

    def override_db():
        request_db = ORMSession(bind=db.get_bind())
        try:
            yield request_db
        finally:
            request_db.close()

    server.app.dependency_overrides[server.get_db] = override_db
    client = TestClient(server.app)
    try:
        first_login = client.post(
            "/api/v1/auth/login",
            json={
                "username": "test-owner",
                "password": "test-owner-password-123",
            },
        )
        assert first_login.status_code == 200
        first_headers = {
            "Authorization": "Bearer " + first_login.json()["access_token"]
        }
        created = client.post(
            "/api/v1/projects",
            headers=first_headers,
            json={
                "name": "First account private project",
                "programme_url": "https://example.com/program",
            },
        )
        assert created.status_code == 201
        private_project_id = created.json()["id"]

        second_login = client.post(
            "/api/v1/auth/login",
            json={
                "username": "second-api-owner",
                "password": "second-api-owner-password-456",
            },
        )
        assert second_login.status_code == 200
        second_headers = {
            "Authorization": "Bearer " + second_login.json()["access_token"]
        }

        assert client.get(
            "/api/v1/projects", headers=second_headers
        ).json() == []
        assert client.get(
            f"/api/v1/projects/{private_project_id}",
            headers=second_headers,
        ).status_code == 404

        # The authenticated account cannot create child records for a project
        # it cannot read, even when it knows the numeric project identifier.
        cross_account_write = client.post(
            f"/api/v1/projects/{private_project_id}/assets",
            headers=second_headers,
            json={"host": "example.com", "included": True, "notes": ""},
        )
        assert cross_account_write.status_code == 404

        assert first_owner_id != second_owner.id
    finally:
        server.app.dependency_overrides.pop(server.get_db, None)
