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
    assert indicator == "Sensitive configuration property names"
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
