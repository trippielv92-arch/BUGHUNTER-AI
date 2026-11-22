import json
from app.services.projects import create_project, add_scope_asset, approve_scope
from app.services import engine


def test_failed_page_requests_consume_limit_and_keep_rate_spacing(db, monkeypatch):
    project = create_project(db, "Engine request cap", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)

    class FakeTransport:
        def __init__(self, hostname):
            assert hostname == "example.com"

        def validate_dns(self):
            return None

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    calls = []

    def fake_read_response(client, url):
        calls.append(url)

        if url.endswith("/robots.txt"):
            return {
                "status": 404,
                "headers": {},
                "body": b"",
                "cookies": [],
                "truncated": False,
            }

        if url == "https://example.com/":
            return {
                "status": 200,
                "headers": {"content-type": "text/html"},
                "body": (
                    b'<a href="/two">two</a>'
                    b'<a href="/three">three</a>'
                    b'<a href="/four">four</a>'
                ),
                "cookies": [],
                "truncated": False,
            }

        raise RuntimeError("simulated connection failure")

    sleeps = []
    progress = []

    monkeypatch.setattr(engine, "PinnedHTTPTransport", FakeTransport)
    monkeypatch.setattr(engine.httpx, "Client", FakeClient)
    monkeypatch.setattr(engine, "_read_limited_response", fake_read_response)
    monkeypatch.setattr(
        engine.time, "sleep", lambda seconds: sleeps.append(seconds)
    )

    stats = engine.run_website_analysis(
        db,
        project.id,
        "https://example.com/",
        max_pages=3,
        delay_seconds=0.5,
        progress_callback=lambda percent, message: progress.append(
            (percent, message)
        ),
    )

    # robots.txt consumes one slot in the shared bounded request budget.
    assert calls[0] == "https://example.com/robots.txt"
    assert stats["robots_requests"] == 1

    # The remaining two slots allow one successful page and one failure.
    assert stats["requests_attempted"] == 2
    assert stats["pages_checked"] == 1
    assert stats["requests_failed"] == 1
    assert stats["request_limit_reached"] is True

    # Failed requests do not bypass the inter-request delay.
    assert sleeps == [0.5, 0.5]

    # Progress reflects all bounded requests, including robots.txt.
    assert [percent for percent, _ in progress] == [66, 94]
    assert "3/3 total requests" in progress[-1][1]


def test_exposure_probe_detects_env_markers_without_returning_values():
    indicator = engine._exposure_probe_indicator(
        "/.env",
        200,
        b"APP_KEY=secret-value\\nDATABASE_URL=postgres://private",
    )
    assert indicator == "Environment-variable configuration markers"
    assert "secret-value" not in indicator


def test_exposure_probe_detects_git_metadata():
    assert engine._exposure_probe_indicator(
        "/.git/HEAD", 200, b"ref: refs/heads/main\\n"
    ) == "Git repository HEAD reference"


def test_exposure_probe_detects_sensitive_config_property_names_only():
    indicator = engine._exposure_probe_indicator(
        "/config.json",
        200,
        b'{"clientSecret":"never-store-this","apiKey":"also-secret"}',
    )
    assert indicator == "Non-empty sensitive configuration field"
    assert "never-store-this" not in indicator


def test_exposure_probe_detects_php_diagnostics():
    assert engine._exposure_probe_indicator(
        "/phpinfo.php",
        200,
        b"PHP Version 8.2 Configuration File (php.ini) Path",
    ) == "PHP configuration diagnostic page"


def test_exposure_probe_detects_apache_server_status():
    assert engine._exposure_probe_indicator(
        "/server-status",
        200,
        b"Apache Server Status Server uptime: 2 days",
    ) == "Apache server-status diagnostic page"


def test_exposure_probe_detects_runtime_diagnostic_property_names():
    assert engine._exposure_probe_indicator(
        "/debug/vars",
        200,
        b'{"cmdline":["server"],"memstats":{"HeapAlloc":100}}',
    ) == "Runtime diagnostic metrics"


def test_exposure_probe_detects_macos_directory_metadata_signature():
    assert engine._exposure_probe_indicator(
        "/.DS_Store", 200, b"Bud1" + b"\\x00" * 20
    ) == "macOS directory metadata file"


def test_exposure_probe_requires_success_and_specific_content_markers():
    assert engine._exposure_probe_indicator(
        "/.env", 403, b"APP_KEY=not-accessible"
    ) is None
    assert engine._exposure_probe_indicator(
        "/.env", 200, b"Welcome to the application"
    ) is None


def test_hunt_request_budget_increased_but_remains_bounded():
    assert engine.MAX_PAGES == 100
    assert len(engine.EXPOSURE_PROBE_PATHS) > 5
    assert "/v3/api-docs" in engine.API_DOCUMENTATION_PATHS


def test_empty_sensitive_config_fields_do_not_trigger_exposure_finding():
    assert engine._exposure_probe_indicator(
        "/config.json",
        200,
        b'{"clientSecret":"","apiKey":null,"databaseUrl":""}',
    ) is None


def test_environment_file_marker_requires_nonempty_value():
    assert engine._exposure_probe_indicator(
        "/.env", 200, b"APP_KEY=\nDATABASE_URL=\n"
    ) is None


def test_anonymous_api_classifier_records_names_not_personal_values():
    body = (
        b'{"profile":{"email":"private@example.test",'
        b'"phoneNumber":"+254700000000","displayName":"Public User"}}'
    )
    fields = engine._anonymous_api_sensitive_fields(
        "application/json", body
    )
    assert fields == ["email", "phoneNumber"]
    assert "private@example.test" not in str(fields)
    assert "+254700000000" not in str(fields)


def test_anonymous_api_classifier_ignores_empty_and_non_json_fields():
    assert engine._anonymous_api_sensitive_fields(
        "application/json",
        b'{"email":"","phone":null,"balance":0}',
    ) == []
    assert engine._anonymous_api_sensitive_fields(
        "text/html", b'{"email":"private@example.test"}'
    ) == []


def test_anonymous_api_endpoint_selection_is_get_only_and_same_host():
    from types import SimpleNamespace

    endpoint = SimpleNamespace(
        method="GET",
        endpoint_type="OpenAPI documented API operation",
        url="https://example.com/api/users?email=private%40example.test",
    )
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) == "https://example.com/api/users"

    endpoint.method = "POST"
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None

    endpoint.method = "GET"
    endpoint.url = "https://outside.example/api/users"
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None


def test_anonymous_api_endpoint_selection_skips_templates_and_risky_routes():
    from types import SimpleNamespace

    endpoint = SimpleNamespace(
        method="GET",
        endpoint_type="Client-side API route",
        url="https://example.com/api/users/{user_id}",
    )
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None

    endpoint.url = "https://example.com/api/logout"
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None

    endpoint.url = "https://example.com/dashboard"
    endpoint.endpoint_type = "Web page"
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None


def test_anonymous_api_assessment_is_explicitly_bounded():
    assert engine.ENDPOINT_ASSESSMENT_LIMIT == 12
    assert engine.MAX_PAGES == 100


def test_anonymous_api_endpoint_selection_skips_concrete_object_identifiers():
    from types import SimpleNamespace

    endpoint = SimpleNamespace(
        method="GET",
        endpoint_type="OpenAPI documented API operation",
        url="https://example.com/api/users/12345",
    )
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None

    endpoint.url = (
        "https://example.com/api/orders/"
        "123e4567-e89b-12d3-a456-426614174000"
    )
    assert engine._safe_anonymous_get_endpoint(
        endpoint, "https://example.com"
    ) is None


def test_run_website_analysis_performs_bounded_anonymous_api_review(
    db, monkeypatch
):
    from app.models.entities import Endpoint

    project = create_project(
        db, "Anonymous API review", "https://example.com"
    )
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)

    db.add(Endpoint(
        project_id=project.id,
        url="https://example.com/api/profile?token=must-not-be-replayed",
        endpoint_type="OpenAPI documented API operation",
        method="GET",
        notes="Test-only discovered API route.",
    ))
    db.add(Endpoint(
        project_id=project.id,
        url="https://example.com/api/profile/update",
        endpoint_type="OpenAPI documented API operation",
        method="POST",
        notes="Must not be requested.",
    ))
    db.commit()

    class FakeTransport:
        def __init__(self, hostname):
            assert hostname == "example.com"

        def validate_dns(self):
            return None

        def close(self):
            return None

    class FakeCookies:
        def __init__(self):
            self.clear_count = 0

        def clear(self):
            self.clear_count += 1

    class FakeClient:
        instance = None

        def __init__(self, **kwargs):
            self.cookies = FakeCookies()
            FakeClient.instance = self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    requests = []

    def fake_read_response(client, url):
        requests.append(url)
        if url.endswith("/robots.txt"):
            return {
                "status": 404, "headers": {}, "body": b"",
                "cookies": [], "truncated": False,
            }
        if url == "https://example.com/":
            return {
                "status": 200,
                "headers": {"content-type": "text/html"},
                "body": b"<html><body>home</body></html>",
                "cookies": [], "truncated": False,
            }
        if url == "https://example.com/api/profile":
            return {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": (
                    b'{"email":"private@example.test",'
                    b'"phoneNumber":"+254700000000"}'
                ),
                "cookies": [], "truncated": False,
            }
        return {
            "status": 404, "headers": {}, "body": b"",
            "cookies": [], "truncated": False,
        }

    monkeypatch.setattr(engine, "PinnedHTTPTransport", FakeTransport)
    monkeypatch.setattr(engine.httpx, "Client", FakeClient)
    monkeypatch.setattr(engine, "_read_limited_response", fake_read_response)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)

    stats = engine.run_website_analysis(
        db,
        project.id,
        "https://example.com/",
        max_pages=30,
        delay_seconds=0.5,
    )

    assert "https://example.com/api/profile" in requests
    assert not any("must-not-be-replayed" in url for url in requests)
    assert "https://example.com/api/profile/update" not in requests
    assert stats["api_endpoints_assessed"] == 1
    assert stats["anonymous_api_responses"] == 1
    assert stats["anonymous_sensitive_field_indicators"] == 2
    assert FakeClient.instance.cookies.clear_count == 2

    finding = db.query(engine.Finding).filter(
        engine.Finding.project_id == project.id,
        engine.Finding.title
        == "Potential unauthenticated API personal-data exposure",
    ).one()
    assert "private@example.test" not in finding.evidence
    assert "+254700000000" not in finding.evidence
    assert "email" in finding.evidence
    assert "phoneNumber" in finding.evidence


def test_credentialed_api_comparison_uses_only_per_request_test_credentials(
    db, monkeypatch
):
    from app.models.entities import Endpoint, ScanCheck

    project = create_project(
        db, "Controlled auth comparison", "https://example.com"
    )
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    db.add(Endpoint(
        project_id=project.id,
        url="https://example.com/api/profile?token=must-not-be-replayed",
        endpoint_type="OpenAPI documented API operation",
        method="GET",
        notes="Test-only discovered API route.",
    ))
    db.commit()

    class FakeTransport:
        def __init__(self, hostname):
            assert hostname == "example.com"

        def validate_dns(self):
            return None

        def close(self):
            return None

    class FakeCookies:
        def __init__(self):
            self.clear_count = 0

        def clear(self):
            self.clear_count += 1

    class FakeClient:
        instance = None

        def __init__(self, **kwargs):
            self.cookies = FakeCookies()
            FakeClient.instance = self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    requests = []

    def fake_read_response(client, url, request_headers=None):
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
                "body": b"<html><body>home</body></html>",
                "cookies": [], "truncated": False,
            }
        if url == "https://example.com/api/profile":
            if not request_headers:
                return {
                    "status": 401,
                    "headers": {"content-type": "application/json"},
                    "body": b'{"detail":"login required"}',
                    "cookies": [], "truncated": False,
                }
            if request_headers.get("Authorization") == "Bearer owner-token":
                return {
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": b'{"email":"owner@example.test"}',
                    "cookies": [], "truncated": False,
                }
            if request_headers.get("Cookie") == "session=standard-token":
                return {
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": b'{"email":"standard@example.test"}',
                    "cookies": [], "truncated": False,
                }
            raise AssertionError("Unexpected authentication header.")
        return {
            "status": 404, "headers": {}, "body": b"",
            "cookies": [], "truncated": False,
        }

    monkeypatch.setattr(engine, "PinnedHTTPTransport", FakeTransport)
    monkeypatch.setattr(engine.httpx, "Client", FakeClient)
    monkeypatch.setattr(engine, "_read_limited_response", fake_read_response)
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)

    profiles = [
        {
            "id": 1, "name": "owner", "role_label": "owner",
            "auth_type": "bearer", "secret": "owner-token",
        },
        {
            "id": 2, "name": "standard", "role_label": "standard",
            "auth_type": "cookie", "secret": "session=standard-token",
        },
    ]
    stats = engine.run_website_analysis(
        db,
        project.id,
        "https://example.com/",
        max_pages=40,
        delay_seconds=0.5,
        auth_profiles=profiles,
    )

    assert stats["credentialed_api_requests"] == 2
    assert stats["credential_profiles_used"] == 2
    assert stats["credentialed_response_differences"] == 2
    assert all(
        url == "https://example.com/api/profile"
        for url, headers in requests
        if headers
    )
    assert any(
        headers == {"Authorization": "Bearer owner-token"}
        for _url, headers in requests
    )
    assert any(
        headers == {"Cookie": "session=standard-token"}
        for _url, headers in requests
    )
    assert FakeClient.instance.cookies.clear_count == 6

    checks = db.query(ScanCheck).filter(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Credentialed API access comparison",
    ).all()
    assert len(checks) == 2
    combined_details = " ".join(check.details for check in checks)
    assert "owner-token" not in combined_details
    assert "standard-token" not in combined_details
    assert "owner@example.test" not in combined_details
    assert "standard@example.test" not in combined_details
    assert "email" in combined_details

    # The engine must persist one endpoint-level comparison across both
    # researcher-owned roles, while retaining a conservative no-difference
    # result when their response metadata is identical.
    assert stats["role_comparisons_completed"] == 1
    assert stats["role_differences_observed"] == 0

    summaries = db.query(ScanCheck).filter(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Role-based authorization evidence summary",
    ).all()
    assert len(summaries) == 1
    summary = json.loads(summaries[0].details)
    assert summary["roles_compared"] == ["owner", "standard"]
    assert summary["behavioral_difference_observed"] is False
    assert summary["automatically_confirmed"] is False
    assert summary["manual_review_required"] is True
    assert "owner-token" not in summaries[0].details
    assert "standard-token" not in summaries[0].details
    assert "owner@example.test" not in summaries[0].details
    assert "standard@example.test" not in summaries[0].details
