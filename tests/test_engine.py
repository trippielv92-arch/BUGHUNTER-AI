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
