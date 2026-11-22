"""Account-isolated persistence for analyzed program policy snapshots."""

import json

from sqlalchemy import func, select

from app.models.entities import Project, ProgramPolicy, ProgramAsset, ScopeAsset
from app.services.analyzer import analyze_programme


def analyze_and_store_program(db, project_id, manual_policy=""):
    project = db.get(Project, project_id)
    if project is None:
        raise ValueError("Project not found or not accessible.")

    if not project.programme_url:
        raise ValueError("This project has no program URL.")

    result = analyze_programme(
        project.programme_url,
        manual_policy=manual_policy,
    )

    fingerprint = result["policy"]["fingerprint_sha256"]

    existing = db.scalar(
        select(ProgramPolicy).where(
            ProgramPolicy.project_id == project_id,
            ProgramPolicy.fingerprint_sha256 == fingerprint,
        )
    )

    if existing is not None:
        return {
            "policy_id": existing.id,
            "version_number": existing.version_number,
            "reused_existing_snapshot": True,
            "analysis": result,
        }

    current_version = db.scalar(
        select(func.max(ProgramPolicy.version_number)).where(
            ProgramPolicy.project_id == project_id
        )
    ) or 0

    # A changed policy invalidates every previous scope approval. The old
    # approvals cannot silently survive a new exclusion or changed rule.
    if current_version > 0 or project.scope_approved:
        project.scope_approved = False
        project.status = "draft"
        for scope_asset in db.scalars(
            select(ScopeAsset).where(ScopeAsset.project_id == project_id)
        ).all():
            scope_asset.approved = False

    provider = result["provider"]
    policy_metadata = result["policy"]

    snapshot = ProgramPolicy(
        project_id=project_id,
        version_number=current_version + 1,
        provider_id=provider["id"],
        provider_name=provider["name"],
        program_identifier=project.programme_url,
        source_url=project.programme_url,
        source_type=result["source"],
        policy_text=result["policy_text"],
        fingerprint_sha256=fingerprint,
        extraction_confidence=policy_metadata["extraction_confidence"],
        extraction_json=json.dumps(
            {
                "provider": provider,
                "policy": policy_metadata,
                "scope": result["scope"],
                "policy_topics": result["policy_topics"],
                "rules": result["rules"],
                "execution_controls": result["execution_controls"],
                "warnings": result["warnings"],
            },
            ensure_ascii=False,
        ),
        review_status="needs_review",
    )

    db.add(snapshot)
    db.flush()

    all_assets = (
        result["scope"]["included_candidates"]
        + result["scope"]["excluded_candidates"]
        + result["scope"]["ambiguous_candidates"]
    )

    for candidate in all_assets:
        db.add(
            ProgramAsset(
                project_id=project_id,
                policy_id=snapshot.id,
                asset=candidate["asset"],
                asset_type=candidate["type"],
                disposition=candidate["disposition"],
                confidence=candidate["confidence"],
                evidence_json=json.dumps(
                    candidate["evidence"],
                    ensure_ascii=False,
                ),
                source=result["source"],
            )
        )

    db.commit()
    db.refresh(snapshot)

    return {
        "policy_id": snapshot.id,
        "version_number": snapshot.version_number,
        "reused_existing_snapshot": False,
        "analysis": result,
    }


def list_program_policies(db, project_id):
    project = db.get(Project, project_id)
    if project is None:
        raise ValueError("Project not found or not accessible.")

    policies = db.scalars(
        select(ProgramPolicy)
        .where(ProgramPolicy.project_id == project_id)
        .order_by(ProgramPolicy.version_number.desc())
    ).all()

    output = []

    for policy in policies:
        assets = db.scalars(
            select(ProgramAsset)
            .where(
                ProgramAsset.project_id == project_id,
                ProgramAsset.policy_id == policy.id,
            )
            .order_by(ProgramAsset.id.asc())
        ).all()

        output.append(
            {
                "id": policy.id,
                "version_number": policy.version_number,
                "provider_id": policy.provider_id,
                "provider_name": policy.provider_name,
                "program_identifier": policy.program_identifier,
                "source_url": policy.source_url,
                "source_type": policy.source_type,
                "fingerprint_sha256": policy.fingerprint_sha256,
                "extraction_confidence": policy.extraction_confidence,
                "review_status": policy.review_status,
                "rules": json.loads(policy.extraction_json or "{}").get("rules", {}),
                "execution_controls": json.loads(policy.extraction_json or "{}").get("execution_controls", {}),
                "warnings": json.loads(policy.extraction_json or "{}").get("warnings", []),
                "created_at": policy.created_at,
                "assets": [
                    {
                        "id": asset.id,
                        "asset": asset.asset,
                        "asset_type": asset.asset_type,
                        "disposition": asset.disposition,
                        "confidence": asset.confidence,
                        "review_status": asset.review_status,
                        "review_note": asset.review_note,
                        "reviewed_at": asset.reviewed_at,
                        "reviewed_by_user_id": asset.reviewed_by_user_id,
                        "evidence": json.loads(asset.evidence_json or "[]"),
                    }
                    for asset in assets
                ],
            }
        )

    return output
