import json

from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services import engine
from app.services.projects import add_scope_asset, approve_scope, create_project
from app.services.validation import validate_project_findings


def _project(db):
    project = create_project(db, "Open redirect review", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def test_external_redirect_with_redirect_parameter_creates_potential_lead(db):
    project = _project(db)
    url = (
        "https://example.com/login?"
        "next=https%3A%2F%2Fevil.example%2Flanding&token=private-token-value"
    )
    result = engine._analyze_open_redirect_response(
        db, project.id, url, 302,
        {"location": "https://evil.example/landing?token=private-token-value"},
    )
    assert result == {"candidate": True, "parameter_count": 1}

    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential open redirect to an external origin",
    ))
    assert finding is not None
    assert finding.status == "potential"
    assert "evil.example" in finding.evidence
    assert "private-token-value" not in finding.evidence
    assert "https://evil.example/landing" not in finding.evidence

    check = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Redirect destination review",
    ))
    details = json.loads(check.details)
    assert details["redirect_parameter_names"] == ["next"]
    assert details["redirect_followed"] is False
    assert details["network_requests_made"] == 0


def test_same_origin_redirect_is_not_an_open_redirect_candidate(db):
    project = _project(db)
    result = engine._analyze_open_redirect_response(
        db, project.id,
        "https://example.com/login?return_to=%2Fdashboard",
        302,
        {"Location": "/dashboard"},
    )
    assert result == {"candidate": False}
    assert db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential open redirect to an external origin",
    )) is None


def test_redirect_without_redirect_like_parameter_is_not_flagged(db):
    project = _project(db)
    result = engine._analyze_open_redirect_response(
        db, project.id,
        "https://example.com/login?campaign=spring",
        302,
        {"Location": "https://identity.example/login"},
    )
    assert result == {"candidate": False}


def test_non_redirect_status_is_ignored(db):
    project = _project(db)
    result = engine._analyze_open_redirect_response(
        db, project.id,
        "https://example.com/login?next=https%3A%2F%2Fevil.example",
        200,
        {"Location": "https://evil.example"},
    )
    assert result == {"candidate": False}


def test_open_redirect_validation_is_supporting_evidence_only(db):
    project = _project(db)
    asset = "https://example.com/login"
    finding = Finding(
        project_id=project.id,
        title="Potential open redirect to an external origin",
        category="Open Redirect Review",
        severity="medium",
        confidence="low",
        status="potential",
        asset=asset,
        description="External redirect candidate.",
        evidence='{"redirect_parameter_names":["next"]}',
        remediation="Validate redirect destinations.",
    )
    db.add(finding)
    db.add(ScanCheck(
        project_id=project.id,
        asset=asset,
        check_name="Redirect destination review",
        outcome="external_redirect_candidate",
        details=json.dumps({
            "redirect_parameter_names": ["next"],
            "redirect_followed": False,
            "network_requests_made": 0,
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
    assert "redirect_parameter_names" in details["indicator_names"]
    assert details["manual_review_required"] is True
    assert details["auto_confirmed"] is False
    assert finding.status == "potential"
