from types import SimpleNamespace

from app.services.assessment_intelligence import (
    build_attack_surface_assessments,
)


def test_query_endpoint_gets_explicit_injection_xss_and_redirect_reviews():
    endpoint = SimpleNamespace(
        id=10,
        url=(
            "https://example.com/api/search?q=synthetic"
            "&redirect=https%3A%2F%2Fexample.org"
        ),
        method="GET",
        endpoint_type="API endpoint",
        notes="",
    )

    result = build_attack_surface_assessments([endpoint])
    scenarios = result["endpoints"][0]["recommendations"]
    titles = {item["title"] for item in scenarios}
    categories = {item["category"] for item in scenarios}

    assert "SQL injection resistance and parameterization review" in titles
    assert "Reflected and DOM XSS context review" in titles
    assert "Redirect destination allowlist and validation" in titles
    assert "Injection" in categories
    assert "XSS" in categories
    assert "Open Redirect" in categories

    assert result["manual_only"] is True
    assert result["network_requests_made"] == 0
    assert result["payloads_executed"] == 0
    assert all(item["manual_only"] for item in scenarios)
    assert all(item["network_requests_by_planner"] == 0 for item in scenarios)
    assert all(item["payloads_executed_by_planner"] == 0 for item in scenarios)


def test_url_input_endpoint_gets_ssrf_review_without_request_execution():
    endpoint = SimpleNamespace(
        id=11,
        url="https://example.com/api/import?source_url=https%3A%2F%2Fexample.org",
        method="POST",
        endpoint_type="API endpoint",
        notes="",
    )

    result = build_attack_surface_assessments([endpoint])
    scenarios = result["endpoints"][0]["recommendations"]
    ssrf = [item for item in scenarios if item["category"] == "SSRF"]

    assert len(ssrf) == 1
    assert ssrf[0]["manual_only"] is True
    assert result["network_requests_made"] == 0
    assert result["payloads_executed"] == 0
