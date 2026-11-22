import json

from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services import engine
from app.services.projects import add_scope_asset, approve_scope, create_project
from app.services.validation import validate_project_findings


def _project(db):
    project = create_project(db, "Reflected XSS review", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def test_unescaped_existing_html_reflection_creates_potential_xss_lead(db):
    project = _project(db)
    value = "<img src=x onerror=alert(1)>"
    url = "https://example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
    body = f"<html><body>{value}</body></html>".encode()

    result = engine._analyze_reflected_query_inputs(
        db, project.id, url, "text/html; charset=utf-8", body
    )
    assert result["reflected_parameters"] == 1
    assert result["unescaped_reflected_parameters"] == 1

    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential reflected XSS from unescaped query input",
    ))
    assert finding is not None
    assert finding.status == "potential"
    assert value not in finding.evidence
    assert '"q"' in finding.evidence
    check = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Query parameter reflection review",
    ))
    details = json.loads(check.details)
    assert value not in check.details
    assert details["query_values_recorded"] is False
    assert details["payloads_executed"] is False


def test_html_escaped_reflection_does_not_create_xss_finding(db):
    project = _project(db)
    url = "https://example.com/search?q=%3Cscript%3Ehello%3C%2Fscript%3E"
    body = b"<html><body>&lt;script&gt;hello&lt;/script&gt;</body></html>"
    result = engine._analyze_reflected_query_inputs(
        db, project.id, url, "text/html", body
    )
    assert result["reflected_parameters"] == 0
    assert result["unescaped_reflected_parameters"] == 0
    assert db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential reflected XSS from unescaped query input",
    )) is None


def test_json_and_truncated_responses_are_not_classified_as_html_xss(db):
    project = _project(db)
    value = "<script>alert(1)</script>"
    url = "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    body = f'{{"echo":"{value}"}}'.encode()
    json_result = engine._analyze_reflected_query_inputs(
        db, project.id, url, "application/json", body
    )
    truncated_result = engine._analyze_reflected_query_inputs(
        db, project.id, url, "text/html", body, truncated=True
    )
    assert json_result["unescaped_reflected_parameters"] == 0
    assert truncated_result["unescaped_reflected_parameters"] == 0


def test_sensitive_query_values_remain_excluded(db):
    project = _project(db)
    url = "https://example.com/search?token=secretvalue&q=ordinaryvalue"
    body = b"<html><body>secretvalue ordinaryvalue</body></html>"
    result = engine._analyze_reflected_query_inputs(
        db, project.id, url, "text/html", body
    )
    assert result["parameters_reviewed"] == 1
    assert result["reflected_parameters"] == 1
    assert result["unescaped_reflected_parameters"] == 0


def test_reflected_xss_validation_is_supporting_evidence_only(db):
    project = _project(db)
    asset = "https://example.com/search"
    finding = Finding(
        project_id=project.id,
        title="Potential reflected XSS from unescaped query input",
        category="XSS",
        severity="medium",
        confidence="low",
        status="potential",
        asset=asset,
        description="Unescaped query reflection.",
        evidence='{"unescaped_reflected_parameter_names":["q"]}',
        remediation="Review output encoding.",
    )
    db.add(finding)
    db.add(ScanCheck(
        project_id=project.id,
        asset=asset,
        check_name="Query parameter reflection review",
        outcome="completed",
        details=json.dumps({
            "unescaped_reflected_parameter_names": ["q"],
            "query_values_recorded": False,
            "payloads_executed": False,
        }),
    ))
    db.commit()

    counts = validate_project_findings(db, project.id)
    assert counts["supported_by_observation"] == 1
    record = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Automated finding validation",
        ScanCheck.asset == asset,
    ))
    details = json.loads(record.details)
    assert "unescaped_reflected_parameter_names" in details["indicator_names"]
    assert details["manual_review_required"] is True
    assert details["auto_confirmed"] is False
    assert finding.status == "potential"


def test_reflection_early_returns_include_all_stats(db):
    project = _project(db)
    result = engine._analyze_reflected_query_inputs(
        db, project.id, "https://example.com/page", "text/html", b"<html></html>"
    )
    assert result == {
        "parameters_reviewed": 0,
        "reflected_parameters": 0,
        "unescaped_reflected_parameters": 0,
    }
