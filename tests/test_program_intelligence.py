import pytest

from app.services.program_intelligence import (
    analyze_program_policy,
    identify_provider,
)


def test_known_provider_detection_and_generic_fallback():
    assert identify_provider(
        "https://hackerone.com/acme"
    )["id"] == "hackerone"
    generic = identify_provider("https://security.example.org/bug-bounty")
    assert generic["id"] == "unknown"
    assert generic["analysis_mode"] == "generic_policy_parser"
    assert generic["adapter_available"] is False


def test_semicolon_separated_scope_labels_are_classified_independently():
    result = analyze_program_policy(
        "https://hackerone.com/acme",
        "In scope app.acme.test; Out of scope legacy.acme.test",
    )
    included = result["scope"]["included_candidates"]
    excluded = result["scope"]["excluded_candidates"]
    assert [item["asset"] for item in included] == ["app.acme.test"]
    assert [item["asset"] for item in excluded] == ["legacy.acme.test"]


def test_exclusion_wins_when_same_hostname_has_conflicting_mentions():
    result = analyze_program_policy(
        "https://bugcrowd.com/acme",
        "In scope: app.acme.test\nOut of scope: app.acme.test",
    )
    assert not result["scope"]["included_candidates"]
    assert [item["asset"] for item in result["scope"]["excluded_candidates"]] == [
        "app.acme.test"
    ]


def test_scope_headings_apply_to_following_asset_lines():
    result = analyze_program_policy(
        "https://intigriti.com/program",
        "In Scope:\nportal.acme.test\napi.acme.test\n"
        "Out of Scope:\nlegacy.acme.test",
    )
    assert {item["asset"] for item in result["scope"]["included_candidates"]} == {
        "portal.acme.test", "api.acme.test"
    }
    assert {item["asset"] for item in result["scope"]["excluded_candidates"]} == {
        "legacy.acme.test"
    }


def test_path_limited_urls_wildcards_and_networks_are_not_plain_hosts():
    result = analyze_program_policy(
        "https://yeswehack.com/program",
        "In scope: https://portal.acme.test/customer-area, *.acme.test, "
        "192.0.2.0/24 and 198.51.100.12",
    )
    assets = {
        item["asset"]: item
        for group in (
            result["scope"]["included_candidates"],
            result["scope"]["excluded_candidates"],
            result["scope"]["ambiguous_candidates"],
        )
        for item in group
    }
    assert assets["https://portal.acme.test/customer-area"]["type"] == "url_path"
    assert assets["*.acme.test"]["type"] == "wildcard_hostname"
    assert assets["192.0.2.0/24"]["type"] == "cidr_network"
    assert assets["198.51.100.12"]["type"] == "ip_address"
    assert "https://portal.acme.test/customer-area" not in {
        item["asset"] for item in result["scope"]["included_candidates"]
        if item["type"] == "hostname"
    }


def test_policy_rules_are_extracted_as_evidence_not_authorization():
    text = (
        "Testing rules: Do not perform denial of service or brute force. "
        "Limit requests to 10 requests per second. "
        "Use test accounts only. Do not publicly disclose findings."
    )
    result = analyze_program_policy("https://program.example.org", text)
    rules = result["rules"]
    assert "prohibited_activities" in rules
    assert "rate_limit_rules" in rules
    assert "authentication_requirements" in rules
    assert "disclosure_requirements" in rules
    assert result["policy"]["human_review_required"] is True
    assert result["scope"]["approval_performed"] is False


def test_provider_domain_is_not_misclassified_as_a_target():
    result = analyze_program_policy(
        "https://hackerone.com/acme",
        "In scope hackerone.com and app.acme.test",
    )
    assert "hackerone.com" not in {
        item["asset"] for item in result["scope"]["included_candidates"]
    }
    assert "app.acme.test" in {
        item["asset"] for item in result["scope"]["included_candidates"]
    }


def test_empty_policy_is_rejected():
    with pytest.raises(ValueError):
        analyze_program_policy("https://example.org/program", "  ")
