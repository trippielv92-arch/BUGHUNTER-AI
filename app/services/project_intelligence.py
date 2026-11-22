"""Unified, read-only project intelligence aggregation."""

from app.models.entities import Endpoint, TestCase, Finding
from app.services.coverage import get_project_coverage
from app.services.assessment_intelligence import (
    build_attack_surface_assessments,
)
from app.services.finding_correlation import (
    analyze_project_finding_duplicates,
)


def build_project_intelligence(
    endpoints,
    test_cases,
    findings,
    coverage,
    duplicate_analysis,
):
    """Combine existing analysis results without modifying source records."""
    assessment = build_attack_surface_assessments(
        endpoints,
        test_cases,
    )

    finding_statuses = {}
    for finding in findings:
        status = str(getattr(finding, "status", "unknown") or "unknown")
        finding_statuses[status] = finding_statuses.get(status, 0) + 1

    potential = finding_statuses.get("potential", 0)
    confirmed = sum(
        count for status, count in finding_statuses.items()
        if status.lower() in {"confirmed", "verified"}
    )

    coverage_summary = (
        coverage.get("summary", {})
        if isinstance(coverage, dict) else {}
    )

    resource_groups = (
        coverage.get("api_resource_groups", [])
        if isinstance(coverage, dict) else []
    )

    duplicate_total = (
        duplicate_analysis.get("exact_group_count", 0)
        + duplicate_analysis.get("possible_pair_count", 0)
    )

    return {
        "assessment": assessment,
        "coverage": coverage,
        "finding_summary": {
            "total": len(findings),
            "by_status": finding_statuses,
            "potential": potential,
            "confirmed_or_verified": confirmed,
        },
        "duplicate_review": duplicate_analysis,
        "review_queue": {
            "potential_findings": potential,
            "exact_duplicate_groups": duplicate_analysis.get(
                "exact_group_count", 0
            ),
            "possible_duplicate_pairs": duplicate_analysis.get(
                "possible_pair_count", 0
            ),
            "assessment_recommendations": assessment["summary"].get(
                "recommendations", 0
            ),
        },
        "resource_summary": {
            "resource_groups": len(resource_groups),
            "api_resource_endpoints": coverage_summary.get(
                "api_resource_endpoints", 0
            ),
            "endpoints_with_recommendations": coverage_summary.get(
                "endpoints_with_recommendations", 0
            ),
            "endpoints_without_recommendations": coverage_summary.get(
                "endpoints_without_recommendations", 0
            ),
        },
        "integrity": {
            "read_only": True,
            "automatic_finding_confirmation": False,
            "automatic_duplicate_merges": 0,
            "automatic_deletions": 0,
            "network_requests_made": 0,
            "payloads_executed": 0,
            "human_review_required": True,
        },
    }


def get_project_intelligence(db, project_id):
    """Load and aggregate intelligence for one existing project."""
    endpoints = (
        db.query(Endpoint)
        .filter(Endpoint.project_id == project_id)
        .order_by(Endpoint.id.asc())
        .all()
    )

    test_cases = (
        db.query(TestCase)
        .filter(TestCase.project_id == project_id)
        .order_by(TestCase.id.asc())
        .all()
    )

    findings = (
        db.query(Finding)
        .filter(Finding.project_id == project_id)
        .order_by(Finding.id.asc())
        .all()
    )

    coverage = get_project_coverage(db, project_id)
    duplicates = analyze_project_finding_duplicates(db, project_id)

    result = build_project_intelligence(
        endpoints,
        test_cases,
        findings,
        coverage,
        duplicates,
    )
    result["project_id"] = project_id
    result["inventory"] = {
        "endpoints": len(endpoints),
        "test_cases": len(test_cases),
        "findings": len(findings),
    }
    return result
