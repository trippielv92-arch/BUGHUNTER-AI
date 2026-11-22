import json

from cryptography.fernet import Fernet
from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services import engine
from app.services.credential_vault import create_test_credential_profile
from app.services.owned_resource_registry import register_researcher_owned_resource
from app.services.projects import add_scope_asset, approve_scope, create_project


class _Cookies:
    def clear(self):
        pass


class _Client:
    def __init__(self):
        self.cookies = _Cookies()


def _resource_fixture(db, monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = create_project(db, "Controlled resource verification", "https://example.com")
    project.policy_text = "Authorized test of example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    owner = create_test_credential_profile(
        db, project.id, "example.com",
        "owner", "owner", "bearer", "owner-test-token",
    )
    requester = create_test_credential_profile(
        db, project.id, "example.com",
        "viewer", "viewer", "bearer", "viewer-test-token",
    )
    resource = register_researcher_owned_resource(
        db, project.id, "example.com",
        "https://example.com/api/orders/{id}", owner.id,
        "synthetic-order-123", "Owner account accessed this synthetic test order.",
    )
    profiles = [
        {"id": owner.id, "role_label": "owner", "auth_type": "bearer",
         "secret": "owner-test-token"},
        {"id": requester.id, "role_label": "viewer", "auth_type": "bearer",
         "secret": "viewer-test-token"},
    ]
    return project, resource, profiles


def _stats():
    return {
        "total_requests": 0,
        "credentialed_api_requests": 0,
        "stopped": False,
        "owned_resource_checks_attempted": 0,
        "owned_resource_owner_checks_passed": 0,
        "cross_account_access_leads": 0,
        "cross_account_access_denied": 0,
        "owned_resource_checks_skipped": 0,
    }


def test_engine_verifies_owner_then_distinct_requester_and_records_potential_lead(
    db, monkeypatch
):
    project, resource, profiles = _resource_fixture(db, monkeypatch)
    requests = []

    def fake_read(client, url, request_headers=None):
        requests.append((url, dict(request_headers or {})))
        assert url == "https://example.com/api/orders/synthetic-order-123"
        if request_headers == {"Authorization": "Bearer owner-test-token"}:
            return {"status": 200, "body": b'{"id":"synthetic-order-123"}',
                    "headers": {}, "truncated": False}
        if request_headers == {"Authorization": "Bearer viewer-test-token"}:
            return {"status": 200, "body": b'{"id":"synthetic-order-123"}',
                    "headers": {}, "truncated": False}
        raise AssertionError("Unexpected account credential.")

    monkeypatch.setattr(engine, "_read_limited_response", fake_read)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)
    stats = _stats()
    remaining = engine._verify_registered_owned_resources(
        db, project.id, "https://example.com", profiles, None, False,
        _Client(), None, 0.5, 100, stats,
    )

    assert len(requests) == 2
    assert stats["owned_resource_owner_checks_passed"] == 1
    assert stats["cross_account_access_leads"] == 1
    assert remaining is False
    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential cross-account access to researcher-owned API resource",
    ))
    assert finding is not None
    assert finding.status == "potential"
    assert finding.confidence == "medium"
    checks = db.scalars(select(ScanCheck).where(
        ScanCheck.project_id == project.id
    )).all()
    serialized = " ".join(check.details for check in checks)
    assert "synthetic-order-123" not in serialized
    assert resource.endpoint_template in {check.asset for check in checks}


def test_engine_never_tests_requester_when_owner_access_fails(db, monkeypatch):
    project, _resource, profiles = _resource_fixture(db, monkeypatch)
    requests = []

    def fake_read(client, url, request_headers=None):
        requests.append(dict(request_headers or {}))
        return {"status": 403, "body": b"", "headers": {}, "truncated": False}

    monkeypatch.setattr(engine, "_read_limited_response", fake_read)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)
    stats = _stats()
    engine._verify_registered_owned_resources(
        db, project.id, "https://example.com", profiles, None, False,
        _Client(), None, 0.5, 100, stats,
    )
    assert requests == [{"Authorization": "Bearer owner-test-token"}]
    assert stats["cross_account_access_leads"] == 0
    assert stats["owned_resource_owner_checks_passed"] == 0


def test_engine_skips_profiles_reusing_owner_credential(db, monkeypatch):
    project, _resource, profiles = _resource_fixture(db, monkeypatch)
    profiles[1]["secret"] = profiles[0]["secret"]
    requests = []

    def fake_read(client, url, request_headers=None):
        requests.append(dict(request_headers or {}))
        return {"status": 200, "body": b"owner", "headers": {}, "truncated": False}

    monkeypatch.setattr(engine, "_read_limited_response", fake_read)
    stats = _stats()
    engine._verify_registered_owned_resources(
        db, project.id, "https://example.com", profiles, None, False,
        _Client(), None, 0.5, 100, stats,
    )
    assert requests == []
    assert stats["owned_resource_checks_skipped"] == 1

def test_full_hunt_reserves_budget_for_registered_resource_verification(
    db, monkeypatch
):
    project, resource, profiles = _resource_fixture(db, monkeypatch)
    requests = []

    class FakeTransport:
        def __init__(self, hostname):
            assert hostname == "example.com"

        def validate_dns(self):
            return None

        def close(self):
            return None

    class FakeCookies:
        def clear(self):
            pass

    class FakeClient:
        def __init__(self, **kwargs):
            self.cookies = FakeCookies()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    target = "https://example.com/api/orders/synthetic-order-123"

    def fake_read(client, url, request_headers=None):
        requests.append((url, dict(request_headers or {})))
        if url.endswith("/robots.txt"):
            return {
                "status": 404, "headers": {}, "body": b"",
                "cookies": [], "truncated": False,
            }
        if url == "https://example.com/":
            return {
                "status": 200,
                "headers": {"content-type": "text/html"},
                "body": b"<html><body>test target</body></html>",
                "cookies": [], "truncated": False,
            }
        if url == target:
            if request_headers == {"Authorization": "Bearer owner-test-token"}:
                return {
                    "status": 200, "headers": {"content-type": "application/json"},
                    "body": b'{"id":"synthetic-order-123"}',
                    "cookies": [], "truncated": False,
                }
            if request_headers == {"Authorization": "Bearer viewer-test-token"}:
                return {
                    "status": 200, "headers": {"content-type": "application/json"},
                    "body": b'{"id":"synthetic-order-123"}',
                    "cookies": [], "truncated": False,
                }
        return {
            "status": 404, "headers": {}, "body": b"",
            "cookies": [], "truncated": False,
        }

    monkeypatch.setattr(engine, "PinnedHTTPTransport", FakeTransport)
    monkeypatch.setattr(engine.httpx, "Client", FakeClient)
    monkeypatch.setattr(engine, "_read_limited_response", fake_read)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)

    stats = engine.run_website_analysis(
        db,
        project.id,
        "https://example.com/",
        max_pages=40,
        delay_seconds=0.5,
        auth_profiles=profiles,
    )

    resource_requests = [
        (url, headers) for url, headers in requests if url == target
    ]
    assert len(resource_requests) == 2
    assert stats["owned_resource_checks_attempted"] == 1
    assert stats["owned_resource_owner_checks_passed"] == 1
    assert stats["cross_account_access_leads"] == 1
    assert stats["credentialed_api_requests"] == 2
    assert stats["total_requests"] <= 40
    assert stats["request_limit_reached"] is False

    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential cross-account access to researcher-owned API resource",
    ))
    assert finding is not None
    assert finding.status == "potential"
    assert "synthetic-order-123" not in finding.evidence
    assert resource.endpoint_template == finding.asset



def test_engine_does_not_test_other_accounts_when_owner_get_is_soft_denied(
    db, monkeypatch
):
    project, _resource, profiles = _resource_fixture(db, monkeypatch)
    requests = []

    def fake_read(client, url, request_headers=None):
        requests.append(dict(request_headers or {}))
        return {
            "status": 200,
            "body": b'{"error":"record not found"}',
            "headers": {"content-type": "application/json"},
            "truncated": False,
        }

    monkeypatch.setattr(engine, "_read_limited_response", fake_read)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)
    stats = _stats()
    engine._verify_registered_owned_resources(
        db, project.id, "https://example.com", profiles, None, False,
        _Client(), None, 0.5, 100, stats,
    )

    assert requests == [{"Authorization": "Bearer owner-test-token"}]
    assert stats["owned_resource_owner_checks_passed"] == 0
    assert stats["cross_account_access_leads"] == 0
    check = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Researcher-owned resource owner-access verification",
        ScanCheck.outcome == "owner_response_not_resource_evidence",
    ))
    assert check is not None
    assert "record not found" not in check.details
