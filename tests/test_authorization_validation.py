import json

from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services.projects import add_scope_asset, approve_scope, create_project
from app.services.validation import validate_project_findings


ASSET = "https://example.com/api/orders/{id}"
TITLE = "Potential cross-account access to researcher-owned API resource"


def _finding(db):
    project = create_project(db, "Authorization validation", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    finding = Finding(
        project_id=project.id,
        title=TITLE,
        category="API Authorization",
        severity="medium",
        confidence="medium",
        status="potential",
        asset=ASSET,
        description="Potential cross-account access.",
        evidence="Owner-first read-only comparison.",
        remediation="Review object-level access policy.",
    )
    db.add(finding)
    db.commit()
    return project, finding


def _add_check(db, project_id, outcome, **details):
    payload = {
        "outcome": outcome,
        "owner_access_attested": True,
        "owner_status": 200,
        "requester_status": 200 if outcome == "potential_cross_account_access" else 403,
        "vulnerability_confirmed": False,
    }
    payload.update(details)
    db.add(ScanCheck(
        project_id=project_id,
        asset=ASSET,
        check_name="Researcher-owned resource cross-account comparison",
        outcome=outcome,
        details=json.dumps(payload),
    ))
    db.commit()


def test_owner_attested_cross_account_success_is_supported_but_not_confirmed(db):
    project, finding = _finding(db)
    _add_check(db, project.id, "potential_cross_account_access")

    counts = validate_project_findings(db, project.id)
    assert counts["supported_by_observation"] == 1

    record = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Automated finding validation",
        ScanCheck.asset == ASSET,
    ))
    details = json.loads(record.details)
    assert record.outcome == "supported_by_observation"
    assert "owner_attested_cross_account_success" in details["indicator_names"]
    assert details["manual_review_required"] is True
    assert details["auto_confirmed"] is False
    assert details["network_requests_made"] == 0
    assert finding.status == "potential"


def test_denied_request_is_not_a_positive_authorization_indicator(db):
    project, _finding_record = _finding(db)
    _add_check(db, project.id, "cross_account_access_denied")

    counts = validate_project_findings(db, project.id)
    assert counts["needs_manual_review"] == 1

    record = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Automated finding validation",
    ))
    details = json.loads(record.details)
    assert details["indicator_names"] == []
    assert details["auto_confirmed"] is False


def test_unattested_or_confirmed_claims_do_not_support_a_finding(db):
    project, _finding_record = _finding(db)
    _add_check(
        db, project.id, "potential_cross_account_access",
        owner_access_attested=False,
    )
    counts = validate_project_findings(db, project.id)
    assert counts["needs_manual_review"] == 1

def test_role_permission_difference_is_supported_but_never_confirmed(db):
    project = create_project(db, "Role comparison validation", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    finding = Finding(
        project_id=project.id,
        title="Potential role-based API authorization difference",
        category="API Authorization",
        severity="medium",
        confidence="low",
        status="potential",
        asset="https://example.com/api/profile",
        description="Role response difference.",
        evidence="Owner and viewer roles differ.",
        remediation="Review role policy.",
    )
    db.add(finding)
    db.add(ScanCheck(
        project_id=project.id,
        asset="https://example.com/api/profile",
        check_name="Role-based authorization evidence summary",
        outcome="difference_observed",
        details=json.dumps({
            "behavioral_difference_observed": True,
            "automatically_confirmed": False,
            "response_values_recorded": False,
            "roles_compared": ["owner", "viewer"],
        }),
    ))
    db.commit()

    counts = validate_project_findings(db, project.id)
    assert counts["supported_by_observation"] == 1

    record = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Automated finding validation",
    ))
    details = json.loads(record.details)
    assert "role_behavioral_difference_observed" in details["indicator_names"]
    assert details["manual_review_required"] is True
    assert details["auto_confirmed"] is False
    assert finding.status == "potential"

