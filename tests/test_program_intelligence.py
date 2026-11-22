import pytest

from app.services.analyzer import analyze_programme
from app.services.program_intelligence import (
    analyze_program_policy,
    derive_policy_execution_controls,
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
        "Use test accounts only. Do not publicly disclose findings. "
        "Eligible vulnerability reports may receive a bounty reward."
    )
    result = analyze_program_policy("https://program.example.org", text)
    rules = result["rules"]
    assert "prohibited_activities" in rules
    assert "rate_limit_rules" in rules
    assert "authentication_requirements" in rules
    assert "disclosure_requirements" in rules
    assert "vulnerability_eligibility" in rules
    assert "reward_and_severity" in rules
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


def test_explicit_automated_scanning_ban_disables_active_crawl():
    controls = derive_policy_execution_controls(
        "Do not use automated scanners against programme assets."
    )
    assert controls["active_automated_testing_allowed"] is False
    assert controls["automated_testing_prohibition_evidence"]


def test_automated_scanning_prohibition_word_order_is_recognized():
    controls = derive_policy_execution_controls(
        "Automated scanning is prohibited."
    )
    assert controls["active_automated_testing_allowed"] is False


def test_strictest_policy_rate_limit_is_converted_to_minimum_delay():
    controls = derive_policy_execution_controls(
        "Limit traffic to 10 requests per second. "
        "The API limit is 30 requests per minute."
    )
    assert controls["rate_limit_requests_per_second"] == pytest.approx(0.5)
    assert controls["minimum_request_delay_seconds"] == pytest.approx(2.0)


def test_hourly_rate_limit_is_not_clamped_to_default_delay():
    controls = derive_policy_execution_controls(
        "Maximum 5 requests per hour."
    )
    assert controls["minimum_request_delay_seconds"] == pytest.approx(720.0)


def test_no_explicit_restriction_keeps_conservative_default():
    controls = derive_policy_execution_controls(
        "Testing is allowed on the listed production web application."
    )
    assert controls["active_automated_testing_allowed"] is True
    assert controls["minimum_request_delay_seconds"] == pytest.approx(0.75)


def test_scope_heading_does_not_leak_into_later_policy_sections():
    result = analyze_program_policy(
        "https://program.example.org",
        "In Scope:\napp.example.org\nProgram Rules:\n"
        "status.example.org is mentioned as an example",
    )
    included = {item["asset"] for item in result["scope"]["included_candidates"]}
    ambiguous = {item["asset"] for item in result["scope"]["ambiguous_candidates"]}
    assert "app.example.org" in included
    assert "status.example.org" in ambiguous


def test_public_html_extraction_preserves_scope_section_boundaries(monkeypatch):
    from app.services import analyzer

    monkeypatch.setattr(
        analyzer,
        "_retrieve_public_page",
        lambda url: (
            "<html><title>Acme Security</title><body>"
            "<h2>In Scope</h2><table><tr><td>portal.acme.test</td></tr></table>"
            "<h2>Out of Scope</h2><ul><li>legacy.acme.test</li></ul>"
            "</body></html>"
        ),
    )
    result = analyze_programme("https://security.example.org/acme")
    assert result["source"] == "public webpage"
    assert "portal.acme.test" in {
        item["asset"] for item in result["scope"]["included_candidates"]
    }
    assert "legacy.acme.test" in {
        item["asset"] for item in result["scope"]["excluded_candidates"]
    }


def test_changed_policy_snapshot_revokes_existing_scope_approval(db):
    from app.models.entities import ScopeAsset
    from app.services.program_policy_store import analyze_and_store_program
    from app.services.projects import add_scope_asset, create_project

    project = create_project(
        db, "Policy change approval reset", "https://program.example.org/acme"
    )
    scope_asset = add_scope_asset(db, project.id, "old.example.org")
    project.policy_text = "Old approved policy text."
    project.scope_approved = True
    scope_asset.approved = True
    db.commit()

    result = analyze_and_store_program(
        db,
        project.id,
        manual_policy=(
            "In Scope:\napp.example.org\n"
            "Out of Scope:\nold.example.org"
        ),
    )
    db.refresh(project)
    db.refresh(scope_asset)

    assert result["version_number"] == 1
    assert project.scope_approved is False
    assert project.status == "draft"
    assert scope_asset.approved is False


def test_identical_policy_snapshot_does_not_create_new_version(db):
    from app.services.program_policy_store import analyze_and_store_program
    from app.services.projects import create_project

    project = create_project(
        db, "Unchanged policy", "https://program.example.org/acme"
    )
    text = "In scope app.example.org"
    first = analyze_and_store_program(db, project.id, manual_policy=text)
    second = analyze_and_store_program(db, project.id, manual_policy=text)

    assert first["version_number"] == 1
    assert second["version_number"] == 1
    assert second["reused_existing_snapshot"] is True
