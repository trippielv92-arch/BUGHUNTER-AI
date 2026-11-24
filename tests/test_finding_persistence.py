from sqlalchemy import select

from app.models.entities import Finding
from app.services.engine import _save_finding
from app.services.projects import create_project


def _save(db, project_id, *, category, asset, evidence="indicator observed"):
    return _save_finding(
        db=db,
        project_id=project_id,
        title="Potential exposed diagnostic endpoint",
        category=category,
        severity="medium",
        confidence="low",
        asset=asset,
        description="A bounded read-only check observed a diagnostic marker.",
        evidence=evidence,
        remediation="Review whether the endpoint should be publicly accessible.",
    )


def test_exact_finding_identity_includes_category(db):
    project = create_project(db, "Finding identity project")

    assert _save(
        db, project.id,
        category="Information Disclosure",
        asset="https://example.test/debug",
    ) is True
    db.commit()

    # A repeat of the same category/title/asset is deduplicated.
    assert _save(
        db, project.id,
        category="Information Disclosure",
        asset="https://example.test/debug",
        evidence="same indicator observed again",
    ) is False

    # A different vulnerability category must not be swallowed by the
    # previous record merely because its title and asset happen to match.
    assert _save(
        db, project.id,
        category="Security Misconfiguration",
        asset="https://example.test/debug",
        evidence="different security property",
    ) is True
    db.commit()

    findings = db.scalars(
        select(Finding).where(Finding.project_id == project.id)
    ).all()
    assert len(findings) == 2
    assert {item.category for item in findings} == {
        "Information Disclosure",
        "Security Misconfiguration",
    }


def test_same_indicator_on_another_asset_is_correlated_without_new_row(db):
    project = create_project(db, "Finding correlation project")

    assert _save(
        db, project.id,
        category="Information Disclosure",
        asset="https://one.example.test/debug",
    ) is True
    db.commit()

    assert _save(
        db, project.id,
        category="Information Disclosure",
        asset="https://two.example.test/debug",
        evidence="same diagnostic marker on second host",
    ) is False
    db.commit()

    findings = db.scalars(
        select(Finding).where(Finding.project_id == project.id)
    ).all()
    assert len(findings) == 1
    assert "two.example.test" in findings[0].evidence
