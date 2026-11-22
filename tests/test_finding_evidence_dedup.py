from sqlalchemy import select

from app.models.entities import Finding
from app.services import engine
from app.services.projects import add_scope_asset, approve_scope, create_project


def _approved_project(db):
    project = create_project(db, "Finding evidence dedup", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def _save(db, project_id, evidence, severity="low", confidence="low"):
    return engine._save_finding(
        db=db,
        project_id=project_id,
        title="Potential cross-account access to researcher-owned API resource",
        category="API Authorization",
        severity=severity,
        confidence=confidence,
        asset="https://example.com/api/orders/{id}",
        description="Potential cross-account access was observed.",
        evidence=evidence,
        remediation="Review object-level authorization.",
    )


def test_exact_duplicate_findings_merge_unique_evidence_without_overwriting(db):
    project = _approved_project(db)
    _save(db, project.id, "Owner profile returned HTTP 200.")
    _save(
        db, project.id, "Viewer profile returned HTTP 200.",
        severity="medium", confidence="medium",
    )
    _save(db, project.id, "Viewer profile returned HTTP 200.")

    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential cross-account access to researcher-owned API resource",
    ))
    assert finding is not None
    assert finding.evidence.count("Owner profile returned HTTP 200.") == 1
    assert finding.evidence.count("Viewer profile returned HTTP 200.") == 1
    assert "Additional evidence observations:" in finding.evidence
    assert finding.severity == "medium"
    assert finding.confidence == "medium"
    assert finding.status == "potential"


def test_dedup_does_not_modify_manually_reviewed_findings(db):
    project = _approved_project(db)
    finding = Finding(
        project_id=project.id,
        title="Potential cross-account access to researcher-owned API resource",
        category="API Authorization",
        severity="low",
        confidence="low",
        status="confirmed",
        asset="https://example.com/api/orders/{id}",
        description="Reviewed description.",
        evidence="Reviewer-approved evidence.",
        remediation="Reviewer-approved remediation.",
    )
    db.add(finding)
    db.commit()

    _save(db, project.id, "New automated observation.", "critical", "high")
    db.refresh(finding)
    assert finding.evidence == "Reviewer-approved evidence."
    assert finding.description == "Reviewed description."
    assert finding.severity == "low"
    assert finding.confidence == "low"
