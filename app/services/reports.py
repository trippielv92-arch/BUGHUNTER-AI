import html
import json
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from sqlalchemy import select

from app.services.coverage import get_project_coverage
from app.services.evidence import audit_project_evidence

from app.models.entities import (
    Project, ScanCheck, Activity, Endpoint, TestCase,
    Evidence, AssessmentJob, FindingReview,
)


def _timestamp(value):
    return value.isoformat() if value else ""


def _split_assessment_notes(notes):
    """Separate worksheet instructions from recorded assessment results."""
    text = str(notes or "").replace("\\n", "\n")
    marker = "ASSESSMENT RESULT"
    worksheet_marker = "MANUAL ASSESSMENT WORKSHEET"

    if marker not in text:
        if worksheet_marker in text:
            return text.strip(), ""
        return "", text.strip()

    before, after = text.split(marker, 1)
    worksheet = before.strip()
    result = after.strip()

    if not worksheet and worksheet_marker in text:
        worksheet = text[:text.index(marker)].strip()

    return worksheet, result


def _validation_source_lines(validation):
    """Return bounded, non-sensitive source-check provenance labels."""
    observations = validation.get("source_observations", [])
    if not isinstance(observations, list):
        observations = []

    lines = []
    for entry in observations[:30]:
        if not isinstance(entry, dict):
            continue

        check_id = entry.get("check_id", entry.get("id", "unknown"))
        check_name = str(entry.get("check_name") or "Unknown check")[:160]
        outcome = str(entry.get("outcome") or "unknown")[:40]
        asset = str(entry.get("asset") or "Asset not recorded")[:300]
        observed_at = str(entry.get("observed_at") or "Time not recorded")[:80]

        lines.append(
            f"Check #{check_id}: {check_name} [{outcome}] | "
            f"{asset} | {observed_at}"
        )

    return lines


def report_data(db, pid):
    project = db.get(Project, pid)
    if not project:
        raise ValueError("Project not found")

    findings = []
    for item in project.findings:
        findings.append({
            "id": item.id,
            "title": item.title,
            "category": item.category,
            "severity": item.severity,
            "confidence": item.confidence,
            "status": item.status,
            "asset": item.asset,
            "description": item.description,
            "evidence": item.evidence,
            "remediation": item.remediation,
            "created_at": _timestamp(item.created_at),
        })

    checks = db.scalars(
        select(ScanCheck)
        .where(ScanCheck.project_id == pid)
        .order_by(ScanCheck.created_at.desc())
    ).all()

    validation_by_finding = {}
    for check in checks:
        if check.check_name != "Automated finding validation":
            continue
        try:
            record = json.loads(check.details or "{}")
        except (TypeError, ValueError):
            continue
        finding_id = record.get("finding_id")
        if (
            record.get("record_type") == "bughunter_validation"
            and isinstance(finding_id, int)
            and finding_id not in validation_by_finding
        ):
            matched = record.get("matched_checks", [])
            if not isinstance(matched, list):
                matched = []

            observations = record.get("source_observations", matched)
            if not isinstance(observations, list):
                observations = matched
            observations = [
                entry for entry in observations[:30]
                if isinstance(entry, dict)
            ]

            source_ids = record.get("source_check_ids", [])
            if not isinstance(source_ids, list):
                source_ids = []
            if not source_ids:
                source_ids = [
                    entry.get("check_id")
                    for entry in observations
                    if isinstance(entry.get("check_id"), int)
                    and not isinstance(entry.get("check_id"), bool)
                ]
            source_ids = [
                value for value in source_ids
                if isinstance(value, int) and not isinstance(value, bool)
            ][:100]

            validation_by_finding[finding_id] = {
                "classification": record.get("classification", "unknown"),
                "family": record.get("family", "unknown"),
                "matched_checks": matched[:100],
                "source_check_ids": source_ids,
                "source_observations": observations,
                "indicator_names": record.get("indicator_names", []),
                "rationale": record.get("rationale", ""),
                "manual_review_required": True,
                "auto_confirmed": False,
                "network_requests_made": 0,
                "payloads_executed": False,
            }

    for finding in findings:
        finding["validation"] = validation_by_finding.get(
            finding["id"],
            {
                "classification": "not_yet_validated",
                "family": "unknown",
                "matched_checks": [],
                "source_check_ids": [],
                "source_observations": [],
                "indicator_names": [],
                "rationale": "No automated validation record is available.",
                "manual_review_required": True,
                "auto_confirmed": False,
                "network_requests_made": 0,
                "payloads_executed": False,
            },
        )

    activities = db.scalars(
        select(Activity)
        .where(Activity.project_id == pid)
        .order_by(Activity.created_at.desc())
    ).all()

    endpoints = db.scalars(
        select(Endpoint)
        .where(Endpoint.project_id == pid)
        .order_by(Endpoint.url)
    ).all()

    test_cases = db.scalars(
        select(TestCase)
        .where(TestCase.project_id == pid)
        .order_by(TestCase.category, TestCase.title)
    ).all()

    evidence_records = db.scalars(
        select(Evidence)
        .where(Evidence.project_id == pid)
        .order_by(Evidence.created_at.desc())
    ).all()

    evidence_audit = audit_project_evidence(db, pid)
    evidence_audit_by_id = {
        item["id"]: item for item in evidence_audit["records"]
    }

    jobs = db.scalars(
        select(AssessmentJob)
        .where(AssessmentJob.project_id == pid)
        .order_by(AssessmentJob.created_at.desc())
    ).all()

    review_records = db.scalars(
        select(FindingReview)
        .where(FindingReview.project_id == pid)
        .order_by(FindingReview.created_at.desc(), FindingReview.id.desc())
    ).all()

    reviews_by_finding = {}
    for record in review_records:
        reviews_by_finding.setdefault(record.finding_id, []).append({
            "id": record.id,
            "reviewer": record.reviewer,
            "previous_status": record.previous_status,
            "new_status": record.new_status,
            "previous_severity": record.previous_severity,
            "new_severity": record.new_severity,
            "previous_confidence": record.previous_confidence,
            "new_confidence": record.new_confidence,
            "notes": record.notes,
            "created_at": _timestamp(record.created_at),
        })

    for finding in findings:
        finding["review_history"] = reviews_by_finding.get(
            finding["id"], []
        )

    # OpenAPI operation assessments are persisted observations. Repeated
    # scans may record the same documented operation more than once.
    openapi_assessments = []
    for check in checks:
        if (
            check.check_name != "OpenAPI documented operation assessment"
            or check.outcome != "completed"
        ):
            continue

        try:
            details = (
                check.details
                if isinstance(check.details, dict)
                else json.loads(check.details or "{}")
            )
        except (TypeError, ValueError):
            continue

        if not isinstance(details, dict):
            continue

        openapi_assessments.append({
            "check_id": check.id,
            "asset": str(check.asset or "")[:500],
            "created_at": _timestamp(check.created_at),
            "method": str(details.get("method") or "")[:16],
            "documented_path": str(details.get("documented_path") or "")[:500],
            "operation_id": str(details.get("operation_id") or "")[:160],
            "security_status": str(details.get("security_status") or "")[:100],
            "security_declared": details.get("security_declared"),
            "security_explicitly_empty": bool(
                details.get("security_explicitly_empty")
            ),
            "identity_parameter_names": [
                str(x)[:100] for x in
                details.get("identity_parameter_names", [])[:40]
                if isinstance(x, (str, int))
            ],
            "sensitive_parameter_names": [
                str(x)[:100] for x in
                details.get("sensitive_parameter_names", [])[:40]
                if isinstance(x, (str, int))
            ],
            "request_body_field_names": [
                str(x)[:100] for x in
                details.get("request_body_field_names", [])[:40]
                if isinstance(x, (str, int))
            ],
            "write_operation": bool(details.get("write_operation")),
            "indicators": [
                str(x)[:240] for x in
                details.get("indicators", [])[:30]
                if isinstance(x, (str, int))
            ],
            "manual_review_required": bool(
                details.get("manual_review_required", True)
            ),
        })

    openapi_counts = {
        "openapi_assessments": len(openapi_assessments),
        "openapi_security_not_declared": sum(
            item["security_declared"] is False
            for item in openapi_assessments
        ),
        "openapi_security_explicitly_empty": sum(
            item["security_explicitly_empty"]
            for item in openapi_assessments
        ),
        "openapi_identity_parameter_assessments": sum(
            bool(item["identity_parameter_names"])
            for item in openapi_assessments
        ),
        "openapi_sensitive_parameter_assessments": sum(
            bool(item["sensitive_parameter_names"])
            for item in openapi_assessments
        ),
        "openapi_write_operation_assessments": sum(
            item["write_operation"] for item in openapi_assessments
        ),
        "openapi_manual_review_required": sum(
            item["manual_review_required"] for item in openapi_assessments
        ),
    }

    counts = {
        "findings": len(findings),
        "confirmed": sum(f["status"].lower() == "confirmed" for f in findings),
        "potential": sum(f["status"].lower() == "potential" for f in findings),
        "needs_review": sum(f["status"].lower() == "needs_review" for f in findings),
        "rejected": sum(f["status"].lower() == "rejected" for f in findings),
        "resolved": sum(f["status"].lower() == "resolved" for f in findings),
        "critical": sum(f["severity"].lower() == "critical" for f in findings),
        "high": sum(f["severity"].lower() == "high" for f in findings),
        "medium": sum(f["severity"].lower() == "medium" for f in findings),
        "low": sum(f["severity"].lower() == "low" for f in findings),
        "info": sum(f["severity"].lower() in ("info", "informational") for f in findings),
        "checks": len(checks),
        "endpoints": len(endpoints),
        "evidence": len(evidence_records),
        "evidence_verified": evidence_audit["summary"]["verified"],
        "evidence_missing": evidence_audit["summary"]["missing"],
        "evidence_invalid_path": evidence_audit["summary"]["invalid_path"],
        "evidence_size_mismatch": evidence_audit["summary"]["size_mismatch"],
        "evidence_hash_mismatch": evidence_audit["summary"]["hash_mismatch"],
        "evidence_broken_reference": evidence_audit["summary"]["broken_reference"],
        "evidence_unlinked": evidence_audit["summary"]["unlinked"],
        "test_cases": len(test_cases),
        "jobs": len(jobs),
        "reviews": len(review_records),
        "validation_supported": sum(
            f["validation"]["classification"] == "supported_by_observation"
            for f in findings
        ),
        "validation_manual_review": sum(
            f["validation"]["classification"] == "needs_manual_review"
            for f in findings
        ),
        "validation_insufficient": sum(
            f["validation"]["classification"] == "insufficient_evidence"
            for f in findings
        ),
        "validation_not_run": sum(
            f["validation"]["classification"] == "not_yet_validated"
            for f in findings
        ),
        **openapi_counts,
    }

    finding_ids = {finding["id"] for finding in findings}
    test_case_ids = {test.id for test in test_cases}
    scan_check_ids = {check.id for check in checks}
    checks_by_id = {
        check.id: check for check in checks if check.id is not None
    }

    source_findings_by_check = {}
    for finding in findings:
        validation = finding.get("validation", {})
        source_ids = validation.get("source_check_ids", [])
        if not isinstance(source_ids, list):
            continue
        for source_id in source_ids:
            if isinstance(source_id, int) and not isinstance(source_id, bool):
                source_findings_by_check.setdefault(
                    source_id, set()
                ).add(finding["id"])

    evidence_by_finding = {}
    for record in evidence_records:
        linked_finding_id = (
            record.finding_id
            if record.finding_id in finding_ids else None
        )
        linked_test_case_id = (
            record.test_case_id
            if record.test_case_id in test_case_ids else None
        )
        linked_scan_check_id = (
            record.scan_check_id
            if record.scan_check_id in scan_check_ids else None
        )
        source_check = checks_by_id.get(linked_scan_check_id)
        source_finding_ids = source_findings_by_check.get(
            linked_scan_check_id, set()
        )
        related_finding_ids = sorted(
            source_finding_ids
            | (
                {linked_finding_id}
                if linked_finding_id is not None else set()
            )
        )

        evidence_item = {
            "id": record.id,
            "name": record.original_name,
            "finding_id": linked_finding_id,
            "test_case_id": linked_test_case_id,
            "scan_check_id": linked_scan_check_id,
            "scan_check_name": (
                source_check.check_name if source_check else None
            ),
            "scan_check_outcome": (
                source_check.outcome if source_check else None
            ),
            "scan_check_asset": (
                source_check.asset if source_check else None
            ),
            "scan_check_observed_at": (
                _timestamp(source_check.created_at) if source_check else None
            ),
            "related_finding_ids": related_finding_ids,
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "content_type": record.content_type,
            "notes": record.notes,
            "created_at": _timestamp(record.created_at),
        }

        for related_finding_id in related_finding_ids:
            attached_item = dict(evidence_item)
            attached_item["finding_link_basis"] = (
                "direct finding link"
                if related_finding_id == linked_finding_id
                else "validation source observation"
            )
            evidence_by_finding.setdefault(
                related_finding_id, []
            ).append(attached_item)

    for finding in findings:
        finding["evidence_files"] = evidence_by_finding.get(
            finding["id"], []
        )

    scan_runs = []
    for activity in activities:
        if activity.event in ("Website analysis completed", "Website analysis stopped"):
            try:
                metrics = json.loads(activity.details or "{}")
                if isinstance(metrics, dict):
                    scan_runs.append({
                        "event": activity.event,
                        "at": _timestamp(activity.created_at),
                        "metrics": metrics,
                    })
            except (TypeError, ValueError):
                continue

    return {
        "project_intelligence": _load_project_intelligence(db, pid),
        "coverage": get_project_coverage(db, pid),
        "scan_runs": scan_runs,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "project": {
            "id": project.id,
            "name": project.name,
            "programme_url": project.programme_url,
            "description": project.description,
            "status": project.status,
            "scope_approved": project.scope_approved,
            "policy_text": project.policy_text,
            "created_at": _timestamp(project.created_at),
        },
        "assets": [
            {
                "host": a.host,
                "included": a.included,
                "approved": a.approved,
                "notes": a.notes,
            }
            for a in project.assets
        ],
        "findings": findings,
        "checks": [
            {
                "asset": c.asset,
                "check": c.check_name,
                "outcome": c.outcome,
                "details": c.details,
                "created_at": _timestamp(c.created_at),
            }
            for c in checks
        ],
        "openapi_assessments": openapi_assessments,
        "endpoints": [
            {
                "url": (
                    e.url.split("?", 1)[0]
                    + ("?[query values redacted]" if "?" in e.url else "")
                ),
                "type": e.endpoint_type,
                "method": e.method,
                "notes": e.notes,
                "created_at": _timestamp(e.created_at),
            }
            for e in endpoints
        ],
        "test_plan": [
            {
                "category": t.category,
                "title": t.title,
                "target": t.target,
                "status": t.status,
                "notes": str(t.notes or "").replace("\\n", "\n"),
                "worksheet": _split_assessment_notes(t.notes)[0],
                "assessment_result": _split_assessment_notes(t.notes)[1],
                "updated_at": _timestamp(t.updated_at),
            }
            for t in test_cases
        ],
        "evidence": [
            {
                "id": e.id,
                "finding_id": (
                    e.finding_id if e.finding_id in finding_ids else None
                ),
                "test_case_id": (
                    e.test_case_id
                    if e.test_case_id in test_case_ids else None
                ),
                "scan_check_id": (
                    e.scan_check_id
                    if e.scan_check_id in scan_check_ids else None
                ),
                "name": e.original_name,
                "sha256": e.sha256,
                "size_bytes": e.size_bytes,
                "file_integrity": evidence_audit_by_id.get(
                    e.id, {}
                ).get("file_integrity", "not_audited"),
                "file_reason": evidence_audit_by_id.get(
                    e.id, {}
                ).get("file_reason", "Audit result unavailable."),
                "reference_integrity": evidence_audit_by_id.get(
                    e.id, {}
                ).get("reference_integrity", "not_audited"),
                "reference_reason": evidence_audit_by_id.get(
                    e.id, {}
                ).get("reference_reason", "Audit result unavailable."),
                "actual_size_bytes": evidence_audit_by_id.get(
                    e.id, {}
                ).get("actual_size_bytes"),
                "content_type": e.content_type,
                "notes": e.notes,
                "created_at": _timestamp(e.created_at),
            }
            for e in evidence_records
        ],
        "evidence_audit": evidence_audit,
        "jobs": [
            {
                "id": j.id,
                "type": j.job_type,
                "status": j.status,
                "progress": j.progress,
                # Export only the user-facing result summary.
                # Internal checkpoints and exception details stay local.
                "result_summary": j.result_summary,
                "created_at": _timestamp(j.created_at),
                "finished_at": _timestamp(j.finished_at),
            }
            for j in jobs
        ],
        "timeline": [
            {
                "event": a.event,
                "details": a.details,
                "at": _timestamp(a.created_at),
            }
            for a in activities
        ],
        "methodology": [
            {
                "title": "Authorization and scope",
                "description": (
                    "Testing must be limited to assets for which explicit "
                    "authorization exists. Recorded project scope and asset "
                    "approvals describe configured boundaries; they do not "
                    "independently establish legal permission from an asset owner."
                ),
            },
            {
                "title": "Automated assessment",
                "description": (
                    "Automated website assessment uses bounded, passive HTTPS "
                    "GET requests, same-host crawling, approved scope checks, "
                    "request limits and response-size limits. It does not perform "
                    "active exploitation, brute force, destructive testing "
                    "or form submissions."
                ),
            },
            {
                "title": "Finding validation",
                "description": (
                    "Automated indicators and potential findings are leads, "
                    "not proof of exploitable vulnerabilities. Findings require "
                    "manual review and reproducible evidence before confirmation."
                ),
            },
            {
                "title": "Guided security checks",
                "description": (
                    "Authorization, object ownership, business logic, race "
                    "condition and payment checks require explicitly authorized "
                    "staging environments, approved test accounts and payment "
                    "sandboxes. Do not use real customer accounts or real "
                    "payments for these checks."
                ),
            },
            {
                "title": "Evidence handling",
                "description": (
                    "Evidence records include file metadata and SHA-256 hashes. "
                    "Reports do not embed original evidence files. Treat reports "
                    "and evidence as confidential security information."
                ),
            },
        ],
        "assessment_note": (
            "This report covers only information recorded by BugHunter AI. "
            "Automated checks are limited and do not constitute a comprehensive "
            "security audit. No findings does not establish that a target is secure. "
            "Potential findings and automated indicators are not confirmed "
            "vulnerabilities. They require manual validation within explicitly "
            "authorized scope before being treated as confirmed or disclosed. "
            "Guided authorization, ownership, business-logic and payment checks "
            "require approved test accounts and staging or payment-sandbox "
            "environments. Evidence files are referenced by metadata and SHA-256 "
            "hash; the files themselves are not embedded in this report."
        ),
    }


def _markdown(data):
    p = data["project"]
    lines = [
        "# BugHunter AI — Security Assessment Report",
        "",
        f"**Project:** {p['name']}",
        f"**Programme:** {p['programme_url'] or 'Not recorded'}",
        f"**Project status:** {p['status']}",
        f"**Scope approval recorded:** {'Yes' if p['scope_approved'] else 'No'}",
        f"**Generated:** {data['generated_at']}",
        "",
        "## Executive summary",
        "",
    ]

    for key, label in [
        ("findings", "Findings"),
        ("confirmed", "Confirmed findings"),
        ("potential", "Potential findings"),
        ("needs_review", "Needs review"),
        ("rejected", "Rejected findings"),
        ("resolved", "Resolved findings"),
        ("critical", "Critical severity"),
        ("high", "High severity"),
        ("medium", "Medium severity"),
        ("low", "Low severity"),
        ("info", "Informational severity"),
        ("checks", "Recorded checks"),
        ("endpoints", "Endpoints"),
        ("evidence", "Evidence records"),
        ("test_cases", "Test-plan entries"),
        ("jobs", "Assessment jobs"),
        ("validation_supported", "Validation: supported observations (not confirmed)"),
        ("validation_manual_review", "Validation: needs manual review"),
        ("validation_insufficient", "Validation: insufficient evidence"),
        ("validation_not_run", "Validation: not yet run"),
        ("openapi_assessments", "OpenAPI operation assessment observations"),
        ("openapi_security_not_declared", "OpenAPI operations without a documented security declaration"),
        ("openapi_security_explicitly_empty", "OpenAPI operations with explicitly empty security requirements"),
        ("openapi_identity_parameter_assessments", "OpenAPI assessments with identity-related parameters"),
        ("openapi_sensitive_parameter_assessments", "OpenAPI assessments with sensitive parameter names"),
        ("openapi_write_operation_assessments", "OpenAPI write-operation assessments"),
        ("openapi_manual_review_required", "OpenAPI assessments requiring manual review"),
    ]:
        lines.append(f"- **{label}:** {data['counts'][key]}" if "counts" in data else "")

    lines += [
        "",
        "## Researcher statement",
        "",
        data.get(
            "researcher_statement",
            "I reviewed the recorded assessment results and distinguish confirmed findings from potential leads and incomplete checks.",
        ),
        "",
    ]

    lines += ["", "## OpenAPI documented-operation assessments", ""]
    if not data.get("openapi_assessments"):
        lines.append("No OpenAPI operation assessment observations recorded.")
    for item in data.get("openapi_assessments", []):
        lines.append(
            f"- Check #{item['check_id']} — {item['method']} "
            f"{item['documented_path']} — operationId: "
            f"{item['operation_id'] or 'not recorded'} — "
            f"security: {item['security_status'] or 'not classified'} — "
            f"identity parameters: "
            f"{', '.join(item['identity_parameter_names']) or 'none recorded'} — "
            f"sensitive parameter names: "
            f"{', '.join(item['sensitive_parameter_names']) or 'none recorded'} — "
            f"write operation: {item['write_operation']} — "
            f"asset: {item['asset']} — recorded: {item['created_at']}"
        )
        if item["indicators"]:
            lines.append(
                "  - Indicators: " + "; ".join(item["indicators"])
            )
    lines += [
        "",
        "These are documentation-based observations, not proof of missing "
        "access controls or exploitable vulnerabilities. An absent security "
        "declaration and an explicitly empty security requirement are distinct "
        "conditions. Documented operations were not invoked by this assessment.",
        "",
    ]

    lines += ["", "## Assessment methodology and authorization", ""]
    for item in data["methodology"]:
        lines += [
            f"### {item['title']}",
            "",
            item["description"],
            "",
        ]

    lines += ["", "## Website scan results", ""]
    if not data.get("scan_runs"):
        lines.append("No website scan runs recorded.")
    for run in data["scan_runs"]:
        lines += [f"### {run['event']} — {run['at']}", ""]
        for key, value in run["metrics"].items():
            label = key.replace("_", " ").capitalize()
            lines.append(f"- **{label}:** {value}")
        lines.append("")

    lines += ["", "## Scope assets", ""]
    if not data["assets"]:
        lines.append("No assets registered.")
    for a in data["assets"]:
        lines.append(
            f"- **{a['host']}** — included: {a['included']}; "
            f"approved: {a['approved']}. {a['notes']}"
        )

    coverage = data["coverage"]
    cs = coverage["summary"]

    lines += [
        "",
        "## Assessment Coverage",
        "",
        f"- **Approved assets:** {cs['approved_assets']}",
        f"- **Assets with recorded assessment checks:** {cs['assessed_assets']}",
        f"- **Assets without recorded assessment checks:** {cs['unassessed_assets']}",
        f"- **Recorded asset coverage:** {cs['asset_coverage_percent']}%",
        f"- **Assessment checks:** {cs['assessment_checks_recorded']}",
        f"- **Endpoints discovered:** {cs['endpoints_discovered']}",
        f"- **Findings recorded:** {cs['findings_recorded']}",
        "",
    ]

    if not coverage["assets"]:
        lines.append("No included and approved assets were available for coverage reporting.")
        lines.append("")

    for asset in coverage["assets"]:
        lines += [
            f"### {asset['host']} — {asset['assessment_status'].replace('_', ' ').title()}",
            "",
            f"- **Checks recorded:** {asset['checks_completed']}",
            f"- **Endpoints:** {asset['endpoints_discovered']}",
            f"- **Findings:** {asset['findings_recorded']}",
            f"- **Last check:** {asset['last_check'] or 'Never'}",
            f"- **Check names:** {', '.join(asset['check_names']) or 'None'}",
            f"- **Targeted test cases:** {asset['test_cases_targeted']}",
            "",
            "**Targeted vulnerability-category coverage:**",
        ]

        if asset["test_categories"]:
            for item in asset["test_categories"]:
                lines.append(
                    f"- **{item['category']}:** "
                    f"{item['completed']}/{item['applicable']} completed "
                    f"({item['completion_percent']}%) — {item['status']}; "
                    f"needs review: {item['needs_review']}; "
                    f"blocked: {item['blocked']}"
                )
        else:
            lines.append("No test cases explicitly assigned to this asset.")

        lines.append("")

    lines += [
        "",
        "## Vulnerability-category test-plan coverage",
        "",
        f"- **Test cases completed:** {cs['test_cases_completed']} / {cs['test_cases_total']}",
        f"- **Overall test-plan completion:** {cs['test_plan_completion_percent']}%",
        f"- **Needs review:** {cs['test_cases_needs_review']}",
        f"- **Blocked:** {cs['test_cases_blocked']}",
        f"- **Not applicable:** {cs['test_cases_not_applicable']}",
        f"- **Unassigned test cases:** {cs['unassigned_test_cases']}",
        "",
    ]

    if not coverage["test_plan"]:
        lines.append("No test plan has been initialized.")
    for category in coverage["test_plan"]:
        lines.append(
            f"- **{category['category']}:** "
            f"{category['completed']}/{category['applicable']} completed "
            f"({category['completion_percent']}%) — {category['status']}; "
            f"needs review: {category['needs_review']}; "
            f"blocked: {category['blocked']}"
        )

    lines += ["", coverage["notice"], ""]

    lines += ["", "## Findings", ""]
    if not data["findings"]:
        lines.append("No findings recorded.")
    for f in data["findings"]:
        lines += [
            f"### #{f['id']} — {f['title']}",
            "",
            (
                "I confirmed this finding only after review."
                if f["status"].lower() == "confirmed"
                else f"I recorded this as a {f['status']} finding; the evidence and validation notes below show what I observed and what still requires review."
            ),
            "",
            f"- **Severity:** {f['severity']}",
            f"- **Confidence:** {f['confidence']}",
            f"- **Status:** {f['status']}",
            f"- **Category:** {f['category']}",
            f"- **Asset:** {f['asset'] or 'Not recorded'}",
            f"- **Created:** {f['created_at']}",
            f"- **Automated validation:** {f['validation']['classification']}",
            f"- **Validation family:** {f['validation']['family']}",
            f"- **Validation indicators:** {', '.join(f['validation']['indicator_names']) or 'None recorded'}",
            f"- **Validation rationale:** {f['validation']['rationale'] or 'Not recorded'}",
            f"- **Source check IDs:** {', '.join(str(value) for value in f['validation'].get('source_check_ids', [])) or 'None recorded'}",
            *(
                f"- **Source observation:** {line}"
                for line in _validation_source_lines(f["validation"])
            ),
            "- **Automatic confirmation:** No",
            "- **Manual review required:** Yes",
            "",
            "**Description**",
            "",
            f["description"] or "Not recorded.",
            "",
            "**Evidence and reproduction observations**",
            "",
            f["evidence"] or "Not recorded.",
            "",
            "**Attached evidence files**",
            "",
            *(
                [
                    f"- Evidence #{e['id']}: {e['name']} — "
                    f"Finding #{e['finding_id'] or 'none'} — "
                    f"Assessment #{e['test_case_id'] or 'none'} — "
                    f"Observation #{e['scan_check_id'] or 'none'} "
                    f"({e.get('scan_check_name') or 'Unknown check'}; "
                    f"{e.get('scan_check_outcome') or 'unknown'}; "
                    f"{e.get('scan_check_asset') or 'asset not recorded'}; "
                    f"{e.get('scan_check_observed_at') or 'time not recorded'}) — "
                    f"Relationship: {e.get('finding_link_basis', 'linked evidence')} — "
                    f"SHA-256 `{e['sha256']}` — "
                    f"{e['size_bytes']} bytes"
                    for e in f["evidence_files"]
                ] or ["No files linked to this finding."]
            ),
            "",
            "**Remediation**",
            "",
            f["remediation"] or "Not recorded.",
            "",
        ]

        lines += ["**Review history**", ""]
        if not f["review_history"]:
            lines.append("No structured review history recorded.")
        for review in f["review_history"]:
            lines.extend([
                f"- **Review #{review['id']}** — {review['created_at']}",
                f"  - Reviewer: {review['reviewer']}",
                f"  - Status: {review['previous_status']} -> {review['new_status']}",
                f"  - Severity: {review['previous_severity']} -> {review['new_severity']}",
                f"  - Confidence: {review['previous_confidence']} -> {review['new_confidence']}",
                f"  - Notes: {review['notes'] or 'None'}",
            ])
        lines.append("")

    lines += ["## Assessment checks", ""]
    for c in data["checks"]:
        lines.append(
            f"- **{c['check']}** — {c['outcome']} — {c['asset']}: {c['details']}"
        )


    lines += ["", "## Endpoint-level assessment coverage", ""]
    endpoint_coverage = data["coverage"]["endpoints"]

    if not endpoint_coverage:
        lines.append("No endpoints registered.")
        lines.append("")

    for endpoint in endpoint_coverage:
        lines += [
            f"### #{endpoint['endpoint_id']} — "
            f"{endpoint['method']} {endpoint['url']}",
            "",
            f"- **Type:** {endpoint['type']}",
            f"- **Classification:** {endpoint['classification']}",
            f"- **Review priority:** {endpoint['priority_band']} "
            f"({endpoint['priority_score']}/100)",
            f"- **Priority signals:** {endpoint['signals_summary']}",
            f"- **Parameter names:** "
            f"{', '.join(endpoint['parameter_names']) or 'None detected'}",
            f"- **Sensitive-looking parameter names:** "
            f"{', '.join(endpoint['sensitive_parameter_names']) or 'None detected'}",
            f"- **Coverage status:** {endpoint['status']}",
            f"- **Completed:** {endpoint['completed']}/{endpoint['applicable']}",
            f"- **Completion:** {endpoint['completion_percent']}%",
            f"- **Needs review:** {endpoint['needs_review']}",
            f"- **Planned:** {endpoint['planned']}",
            f"- **In progress:** {endpoint['in_progress']}",
            f"- **Blocked:** {endpoint['blocked']}",
            f"- **Not applicable:** {endpoint['not_applicable']}",
            "",
            "**Recommended assessment tasks:**",
        ]

        if endpoint["test_cases"]:
            for test in endpoint["test_cases"]:
                lines.append(
                    f"- [{test['status']}] {test['category']} — "
                    f"{test['title']}"
                )
        else:
            lines.append("No endpoint-specific recommendations recorded.")

        lines.append("")

    lines += [
        "Endpoint coverage reflects recorded manual assessment tasks. "
        "It is not proof that an endpoint is secure. A task marked "
        "'Finding identified' remains subject to evidence-based review. "
        "Endpoint priority is a metadata-based manual-review heuristic, "
        "not vulnerability severity or proof of exploitability. "
        "Query parameter values are redacted in report URLs.",
        "",
    ]

    lines += ["", "## API resource relationship map", ""]
    resource_groups = data["coverage"].get("api_resource_groups", [])
    if not resource_groups:
        lines.append("No API resource groups identified in the endpoint inventory.")
    for group in resource_groups:
        lines.append(
            f"### `{group['resource_path']}`"
        )
        lines.append(
            f"- **Observed methods:** {', '.join(group['methods']) or 'None'}"
        )
        lines.append(
            f"- **Collection methods:** {', '.join(group['collection_methods']) or 'None'}"
        )
        lines.append(
            f"- **Individual-resource methods:** {', '.join(group['item_methods']) or 'None'}"
        )
        lines.append(
            f"- **Endpoints:** {group['endpoint_count']}"
        )
        lines.append(
            f"- **Assessment progress:** {group.get('assessment_summary', 'No tasks recorded')}"
        )
        lines.append(
            f"- **Authorization progress:** {group.get('authorization_summary', 'No authorization tasks recorded')}"
        )
        lines.append(
            f"- **Assessment tasks:** {group.get('assessment_task_count', 0)}"
        )
        lines.append(
            f"- **Identifier parameters:** {', '.join(group['identifier_parameters']) or 'None detected'}"
        )
        signals = group.get("authorization_review_signals", [])
        lines.append(
            "- **Authorization review signals:** "
            + (", ".join(signals) if signals else "None specifically detected")
        )
        if group["parent_resource"]:
            lines.append(f"- **Parent resource:** `{group['parent_resource']}`")
        if group["not_observed"]:
            gaps = ", ".join(
                f"{item['method']} ({item['route_type']})"
                for item in group["not_observed"]
            )
            lines.append(f"- **Not observed; review if applicable:** {gaps}")
        for route in group["routes"]:
            lines.append(
                f"- `{route['method']} {route['path']}` "
                f"(endpoint #{route['endpoint_id']})"
            )
        lines.append(f"- {group['review_note']}")
        lines.append(f"- {group.get('progress_note', '')}")
        lines.append("")

    lines += ["", "## Vulnerability-specific assessment scenarios", ""]
    scenarios = data["coverage"].get("assessment_scenarios", [])
    if not scenarios:
        lines.append("No metadata-driven scenarios generated.")
    for scenario in scenarios:
        lines += [
            f"### {scenario['category']} — {scenario['title']}",
            "",
            f"- **Endpoint:** `{scenario['method']} {scenario['target']}`",
            f"- **Endpoint ID:** {scenario['endpoint_id']}",
            f"- **Review priority:** {scenario['review_priority']}",
            f"- **Status:** {scenario['status']}",
            f"- **Trigger:** {scenario['trigger']}",
            f"- **Mode:** {scenario['automation_mode']}",
            "",
            "**Safe assessment steps**",
            "",
        ]
        lines.extend(f"- {step}" for step in scenario["safe_steps"])
        lines += ["", "**Evidence checklist**", ""]
        lines.extend(f"- {item}" for item in scenario["evidence_to_record"])
        lines.append("")

    lines += ["", "## Attack surface inventory", ""]
    for e in data["endpoints"]:
        lines.append(f"- `{e['method']} {e['url']}` — {e['type']}: {e['notes']}")

    lines += ["", "## Manual test plan", ""]
    for t in data["test_plan"]:
        lines += [
            f"### {t['category']} / {t['title']}",
            "",
            f"- **Status:** {t['status']}",
            f"- **Target:** {t['target'] or 'Not assigned'}",
            "",
            "**Manual worksheet and instructions**",
            "",
            t["worksheet"] or "No generated worksheet recorded.",
            "",
            "**Assessment result and observations**",
            "",
            t["assessment_result"] or "No assessment result recorded.",
            "",
        ]

    audit_summary = data["evidence_audit"]["summary"]
    lines += [
        "",
        "## Evidence integrity audit",
        "",
        f"- Total files: {audit_summary['total']}",
        f"- Verified: {audit_summary['verified']}",
        f"- Missing: {audit_summary['missing']}",
        f"- Invalid paths: {audit_summary['invalid_path']}",
        f"- Size mismatches: {audit_summary['size_mismatch']}",
        f"- SHA-256 mismatches: {audit_summary['hash_mismatch']}",
        f"- Broken links: {audit_summary['broken_reference']}",
        f"- Unlinked files: {audit_summary['unlinked']}",
        "",
        "This is a read-only audit. Mismatches indicate differences from stored "
        "metadata and do not by themselves establish malicious alteration.",
        "",
    ]
    lines += ["", "## Evidence register", ""]
    for e in data["evidence"]:
        lines.append(
            f"- Evidence #{e['id']}: {e['name']} — "
            f"Finding: #{e['finding_id'] or 'none'} — "
            f"Assessment: #{e['test_case_id'] or 'none'} — "
            f"Observation: #{e['scan_check_id'] or 'none'} — "
            f"SHA-256 `{e['sha256']}` — {e['size_bytes']} bytes — "
            f"File integrity: {e['file_integrity']} — "
            f"References: {e['reference_integrity']} — "
            f"{e['file_reason']} — {e['reference_reason']} — "
            f"{e['notes'] or 'No notes recorded.'}"
        )

    lines += ["", "## Assessment jobs", ""]
    for j in data["jobs"]:
        lines.append(
            f"- Job #{j['id']} — {j['type']} — {j['status']} "
            f"({j['progress']}%): {j['result_summary'] or 'No summary recorded.'}"
        )

    lines += ["", "## Activity timeline", ""]
    for a in data["timeline"]:
        lines.append(f"- {a['at']} — **{a['event']}**: {a['details']}")

    lines += _project_intelligence_markdown(data)
    lines += ["", "## Limitations", "", data["assessment_note"], ""]
    return "\n".join(line for line in lines if line is not None)


def _html_report(data):
    p = data["project"]

    def esc(value):
        return html.escape(str(value if value is not None else ""))

    def section(title, content):
        return f"<section><h2>{esc(title)}</h2>{content}</section>"

    assets = "".join(
        f"<tr><td>{esc(a['host'])}</td><td>{a['included']}</td>"
        f"<td>{a['approved']}</td><td>{esc(a['notes'])}</td></tr>"
        for a in data["assets"]
    ) or "<tr><td colspan='4'>No assets recorded</td></tr>"

    coverage = data["coverage"]
    cs = coverage["summary"]

    coverage_summary = (
        f"<p><b>Approved assets:</b> {cs['approved_assets']} &nbsp; "
        f"<b>Assessed:</b> {cs['assessed_assets']} &nbsp; "
        f"<b>Not assessed:</b> {cs['unassessed_assets']} &nbsp; "
        f"<b>Recorded coverage:</b> {cs['asset_coverage_percent']}%</p>"
        f"<p><b>Assessment checks:</b> {cs['assessment_checks_recorded']} &nbsp; "
        f"<b>Endpoints:</b> {cs['endpoints_discovered']} &nbsp; "
        f"<b>Findings:</b> {cs['findings_recorded']}</p>"
    )

    coverage_rows = "".join(
        "<tr>"
        f"<td>{esc(a['host'])}</td>"
        f"<td>{esc(a['assessment_status'])}</td>"
        f"<td>{a['checks_completed']}</td>"
        f"<td>{a['endpoints_discovered']}</td>"
        f"<td>{a['findings_recorded']}</td>"
        f"<td>{esc(a['last_check'] or 'Never')}</td>"
        f"<td>{esc(', '.join(a['check_names']) or 'None')}</td>"
        "</tr>"
        for a in coverage["assets"]
    ) or "<tr><td colspan='7'>No included and approved assets</td></tr>"

    asset_category_rows = ""

    for asset in coverage["assets"]:
        if not asset["test_categories"]:
            asset_category_rows += (
                "<tr>"
                f"<td>{esc(asset['host'])}</td>"
                "<td colspan='6'>No test cases explicitly assigned</td>"
                "</tr>"
            )
            continue

        for item in asset["test_categories"]:
            asset_category_rows += (
                "<tr>"
                f"<td>{esc(asset['host'])}</td>"
                f"<td>{esc(item['category'])}</td>"
                f"<td>{item['completed']}/{item['applicable']}</td>"
                f"<td>{item['completion_percent']}%</td>"
                f"<td>{esc(item['status'])}</td>"
                f"<td>{item['needs_review']}</td>"
                f"<td>{item['blocked']}</td>"
                "</tr>"
            )

    if not coverage["assets"]:
        asset_category_rows = (
            "<tr><td colspan='7'>No approved assets</td></tr>"
        )

    asset_category_html = (
        "<h3>Per-asset vulnerability-category coverage</h3>"
        "<table><tr><th>Asset</th><th>Category</th>"
        "<th>Completed / applicable</th><th>Progress</th>"
        "<th>Status</th><th>Needs review</th><th>Blocked</th></tr>"
        f"{asset_category_rows}</table>"
    )

    category_rows = "".join(
        "<tr>"
        f"<td>{esc(item['category'])}</td>"
        f"<td>{item['completed']}/{item['applicable']}</td>"
        f"<td>{item['completion_percent']}%</td>"
        f"<td>{esc(item['status'])}</td>"
        f"<td>{item['needs_review']}</td>"
        f"<td>{item['blocked']}</td>"
        "</tr>"
        for item in coverage["test_plan"]
    ) or "<tr><td colspan='6'>No test plan initialized</td></tr>"

    category_html = (
        "<h3>Vulnerability-category test-plan coverage</h3>"
        f"<p><b>Completed:</b> {cs['test_cases_completed']} / "
        f"{cs['test_cases_total']} &nbsp; "
        f"<b>Overall progress:</b> {cs['test_plan_completion_percent']}% "
        f"&nbsp; <b>Unassigned:</b> {cs['unassigned_test_cases']}</p>"
        f"<p><b>Needs review:</b> {cs['test_cases_needs_review']} &nbsp; "
        f"<b>Blocked:</b> {cs['test_cases_blocked']} &nbsp; "
        f"<b>Not applicable:</b> {cs['test_cases_not_applicable']}</p>"
        "<table><tr><th>Category</th><th>Completed / applicable</th>"
        "<th>Progress</th><th>Status</th><th>Needs review</th>"
        f"<th>Blocked</th></tr>{category_rows}</table>"
    )


    endpoint_coverage_rows = ""
    for endpoint in coverage["endpoints"]:
        endpoint_coverage_rows += (
            "<tr>"
            f"<td>#{endpoint['endpoint_id']} "
            f"{esc(endpoint['method'])} {esc(endpoint['url'])}</td>"
            f"<td>{esc(endpoint['classification'])}</td>"
            f"<td>{esc(endpoint['priority_band'])} "
            f"({endpoint['priority_score']}/100)</td>"
            f"<td>{esc(endpoint['signals_summary'])}</td>"
            f"<td>{esc(endpoint['status'])}</td>"
            f"<td>{endpoint['completed']}/{endpoint['applicable']}</td>"
            f"<td>{endpoint['completion_percent']}%</td>"
            f"<td>{endpoint['needs_review']}</td>"
            f"<td>{endpoint['planned']}</td>"
            f"<td>{endpoint['blocked']}</td>"
            "</tr>"
        )

    if not endpoint_coverage_rows:
        endpoint_coverage_rows = (
            "<tr><td colspan='10'>No endpoints registered</td></tr>"
        )

    endpoint_coverage_html = (
        "<h3>Endpoint-level assessment coverage</h3>"
        "<table><tr><th>Endpoint</th><th>Classification</th>"
        "<th>Review priority</th><th>Signals</th><th>Status</th>"
        "<th>Completed / applicable</th><th>Progress</th>"
        "<th>Needs review</th><th>Planned</th><th>Blocked</th></tr>"
        f"{endpoint_coverage_rows}</table>"
        "<p><small>Coverage reflects recorded assessment tasks, "
        "not proof that an endpoint is secure. Findings require "
        "evidence-based review.</small></p>"
    )

    resource_group_rows = ""
    for group in coverage.get("api_resource_groups", []):
        methods = ", ".join(group["methods"]) or "None"
        identifiers = ", ".join(group["identifier_parameters"]) or "None"
        authorization_signals = ", ".join(
            group.get("authorization_review_signals", [])
        ) or "None specifically detected"
        missing = ", ".join(
            f"{item['method']} ({item['route_type']})"
            for item in group["not_observed"]
        ) or "None recorded"

        routes = "<br>".join(
            esc(f"{route['method']} {route['path']} "
                f"(#{route['endpoint_id']})")
            for route in group["routes"]
        )

        resource_group_rows += (
            "<tr>"
            f"<td><code>{esc(group['resource_path'])}</code></td>"
            f"<td>{esc(methods)}</td>"
            f"<td>{group['endpoint_count']}</td>"
            f"<td>{esc(group.get('assessment_summary', 'No tasks recorded'))}</td>"
            f"<td>{esc(group.get('authorization_summary', 'No authorization tasks recorded'))}</td>"
            f"<td>{esc(identifiers)}</td>"
            f"<td>{esc(authorization_signals)}</td>"
            f"<td>{esc(group['parent_resource'] or 'None')}</td>"
            f"<td>{esc(missing)}</td>"
            f"<td>{routes}</td>"
            "</tr>"
        )

    if not resource_group_rows:
        resource_group_rows = (
            "<tr><td colspan='10'>No API resource groups identified</td></tr>"
        )

    resource_group_html = (
        "<h3>API resource relationship map</h3>"
        "<table><tr><th>Resource</th><th>Observed methods</th>"
        "<th>Endpoints</th><th>Assessment progress</th>"
        "<th>Authorization progress</th><th>Identifier parameters</th>"
        "<th>Authorization review signals</th>"
        "<th>Parent resource</th><th>Not observed; review if applicable</th>"
        "<th>Registered routes</th></tr>"
        f"{resource_group_rows}</table>"
        "<p><small>Missing operations are inventory observations, "
        "not confirmed vulnerabilities. Progress is based on recorded "
        "manual tasks. Finding identified requires evidence-based review. "
        "Routes sharing a URL may share task counts.</small></p>"
    )

    scenario_html_rows = ""
    for scenario in coverage.get("assessment_scenarios", []):
        steps = "<ol>" + "".join(
            f"<li>{esc(step)}</li>" for step in scenario["safe_steps"]
        ) + "</ol>"
        evidence = "<ul>" + "".join(
            f"<li>{esc(item)}</li>" for item in scenario["evidence_to_record"]
        ) + "</ul>"
        scenario_html_rows += (
            "<article>"
            f"<h4>{esc(scenario['category'])}: {esc(scenario['title'])}</h4>"
            f"<p><b>Endpoint:</b> {esc(scenario['method'])} {esc(scenario['target'])}<br>"
            f"<b>Priority:</b> {esc(scenario['review_priority'])}<br>"
            f"<b>Status:</b> {esc(scenario['status'])}<br>"
            f"<b>Trigger:</b> {esc(scenario['trigger'])}</p>"
            f"<b>Safe steps</b>{steps}<b>Evidence checklist</b>{evidence}"
            "</article>"
        )
    assessment_scenarios_html = (
        "<h3>Vulnerability-specific assessment scenarios</h3>"
        + (scenario_html_rows or "<p>No scenarios generated.</p>")
        + "<p><small>Plans are not vulnerability confirmations.</small></p>"
    )

    coverage_html = (
        coverage_summary
        + endpoint_coverage_html
        + resource_group_html
        + assessment_scenarios_html
        + category_html
        + asset_category_html
        + "<table><tr><th>Asset</th><th>Status</th><th>Checks</th>"
        "<th>Endpoints</th><th>Findings</th><th>Last check</th>"
        f"<th>Check names</th></tr>{coverage_rows}</table>"
        f"<p><small>{esc(coverage['notice'])}</small></p>"
    )

    findings = ""
    for f in data["findings"]:
        linked_evidence = "".join(
            f"<li>Evidence #{e['id']}: {esc(e['name'])} — "
            f"Finding #{e['finding_id'] or 'none'} — "
            f"Assessment #{e['test_case_id'] or 'none'} — "
            f"Observation #{e['scan_check_id'] or 'none'} — "
            f"{esc(e.get('scan_check_name') or 'Unknown check')} "
            f"[{esc(e.get('scan_check_outcome') or 'unknown')}] — "
            f"Asset: {esc(e.get('scan_check_asset') or 'Not recorded')} — "
            f"Observed: {esc(e.get('scan_check_observed_at') or 'Not recorded')} — "
            f"Relationship: {esc(e.get('finding_link_basis', 'linked evidence'))} — "
            f"SHA-256 <code>{esc(e['sha256'])}</code> — "
            f"{e['size_bytes']} bytes</li>"
            for e in f["evidence_files"]
        ) or "<li>No files linked to this finding.</li>"

        review_history = "".join(
            "<li>"
            f"<b>{esc(r['created_at'])}</b> — "
            f"{esc(r['reviewer'])}; "
            f"status: {esc(r['previous_status'])} -> {esc(r['new_status'])}; "
            f"severity: {esc(r['previous_severity'])} -> {esc(r['new_severity'])}; "
            f"confidence: {esc(r['previous_confidence'])} -> {esc(r['new_confidence'])}; "
            f"notes: {esc(r['notes'] or 'None')}"
            "</li>"
            for r in f["review_history"]
        ) or "<li>No structured review history recorded.</li>"

        validation = f["validation"]
        validation_html = (
            "<h4>Automated validation — not a confirmation</h4>"
            f"<p><b>Classification:</b> {esc(validation['classification'])}<br>"
            f"<b>Family:</b> {esc(validation['family'])}<br>"
            f"<b>Indicators:</b> {esc(', '.join(validation['indicator_names']) or 'None recorded')}<br>"
            f"<b>Rationale:</b> {esc(validation['rationale'] or 'Not recorded')}<br>"
            "<b>Automatically confirmed:</b> No<br>"
            "<b>Manual review required:</b> Yes</p>"
        )
        source_ids_html = esc(
            ", ".join(str(value) for value in validation.get("source_check_ids", []))
            or "None recorded"
        )
        source_lines_html = "<br>".join(
            esc(line) for line in _validation_source_lines(validation)
        ) or "No source observations recorded."
        source_html = (
            "<h4>Validation source provenance</h4>"
            f"<p><b>Source check IDs:</b> {source_ids_html}<br>"
            f"{source_lines_html}</p>"
        )

        findings += (
            "<article class='finding'>"
            f"<h3>#{f['id']} — {esc(f['title'])}</h3>"
            f"<p><b>Severity:</b> {esc(f['severity'])} &nbsp; "
            f"<b>Confidence:</b> {esc(f['confidence'])} &nbsp; "
            f"<b>Status:</b> {esc(f['status'])}</p>"
            f"<p><b>Category:</b> {esc(f['category'])} &nbsp; "
            f"<b>Asset:</b> {esc(f['asset'])}</p>"
            f"<h4>Description</h4><pre>{esc(f['description'])}</pre>"
            f"<h4>Evidence and observations</h4><pre>{esc(f['evidence'])}</pre>"
            f"{validation_html}{source_html}"
            f"<h4>Attached evidence files</h4><ul>{linked_evidence}</ul>"
            f"<h4>Remediation</h4><pre>{esc(f['remediation'])}</pre>"
            f"<h4>Review history</h4><ul>{review_history}</ul>"
            "</article>"
        )
    if not findings:
        findings = "<p>No findings recorded.</p>"

    def rows(items, fields):
        if not items:
            return "<tr><td colspan='8'>No records</td></tr>"
        return "".join(
            "<tr>" + "".join(f"<td>{esc(item.get(field, ''))}</td>" for field in fields) + "</tr>"
            for item in items
        )

    test_plan_rows = "".join(
        "<tr>"
        f"<td>{esc(item['category'])}</td>"
        f"<td>{esc(item['title'])}</td>"
        f"<td>{esc(item['status'])}</td>"
        f"<td>{esc(item['target'])}</td>"
        f"<td><pre>{esc(item['worksheet'] or 'No worksheet recorded.')}</pre></td>"
        f"<td><pre>{esc(item['assessment_result'] or 'No result recorded.')}</pre></td>"
        "</tr>"
        for item in data["test_plan"]
    ) or "<tr><td colspan='6'>No test cases recorded</td></tr>"

    scan_sections = []
    for run in data.get("scan_runs", []):
        metric_rows = "".join(
            f"<tr><th>{esc(key.replace('_', ' ').capitalize())}</th>"
            f"<td>{esc(value)}</td></tr>"
            for key, value in run["metrics"].items()
        )
        scan_sections.append(
            f"<h3>{esc(run['event'])} — {esc(run['at'])}</h3>"
            f"<table>{metric_rows}</table>"
        )
    scan_html = "".join(scan_sections) or "<p>No website scan runs recorded.</p>"

    counts = data["counts"]
    summary = "".join(
        f"<div class='metric'><b>{counts[k]}</b><span>{esc(label)}</span></div>"
        for k, label in [
            ("findings", "Findings"),
            ("confirmed", "Confirmed"),
            ("potential", "Potential"),
            ("needs_review", "Needs review"),
            ("resolved", "Resolved"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Informational"),
            ("checks", "Checks"),
            ("endpoints", "Endpoints"),
            ("evidence", "Evidence"),
            ("validation_supported", "Validation supported observations (not confirmed)"),
            ("validation_manual_review", "Validation needs manual review"),
            ("validation_insufficient", "Validation insufficient evidence"),
            ("validation_not_run", "Validation not yet run"),
            ("openapi_assessments", "OpenAPI assessment observations"),
            ("openapi_security_not_declared", "Security not declared"),
            ("openapi_security_explicitly_empty", "Security explicitly empty"),
            ("openapi_identity_parameter_assessments", "Identity parameter assessments"),
            ("openapi_sensitive_parameter_assessments", "Sensitive parameter assessments"),
            ("openapi_write_operation_assessments", "Write-operation assessments"),
            ("openapi_manual_review_required", "Manual review required"),
        ]
    )

    openapi_rows = "".join(
        "<tr>"
        f"<td>{esc(item['check_id'])}</td>"
        f"<td>{esc(item['method'])}</td>"
        f"<td>{esc(item['documented_path'])}</td>"
        f"<td>{esc(item['operation_id'])}</td>"
        f"<td>{esc(item['security_status'])}</td>"
        f"<td>{esc(', '.join(item['identity_parameter_names']))}</td>"
        f"<td>{esc(', '.join(item['sensitive_parameter_names']))}</td>"
        f"<td>{esc('; '.join(item['indicators']))}</td>"
        f"<td>{esc(item['asset'])}</td>"
        f"<td>{esc(item['created_at'])}</td>"
        "</tr>"
        for item in data.get("openapi_assessments", [])
    ) or "<tr><td colspan='10'>No OpenAPI operation assessments recorded</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BugHunter AI Report — {esc(p['name'])}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#eef2f7;color:#172337;font:15px/1.6 Arial,sans-serif}}
header{{background:#101d32;color:white;padding:38px max(calc((100% - 1050px)/2),24px)}}
header h1{{margin:0 0 8px;font-size:30px}}
main{{max-width:1050px;margin:28px auto;padding:0 22px}}
section,.finding{{background:white;border:1px solid #dbe3ee;border-radius:10px;padding:22px;margin:18px 0}}
h2{{color:#145ca5;border-bottom:1px solid #e2e8f0;padding-bottom:8px}}
h3{{margin-top:0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;background:#f5f7fa;padding:12px;border-radius:6px}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:12px}}
.metric{{background:#eaf2fc;padding:15px;border-radius:8px;display:flex;flex-direction:column}}
.metric b{{font-size:25px;color:#145ca5}}small,footer{{color:#607087}}
@media print{{body{{background:white}}section,.finding{{break-inside:avoid;box-shadow:none}}}}
</style></head>
<body>
<header><h1>BugHunter AI</h1><div>Security Assessment Report</div>
<p>{esc(p['name'])} · Generated {esc(data['generated_at'])}</p></header>
<main>
{section("Project overview", f"<p><b>Programme:</b> {esc(p['programme_url'])}</p><p><b>Status:</b> {esc(p['status'])}</p><p><b>Scope approval recorded:</b> {p['scope_approved']}</p><p>{esc(p['description'])}</p>")}
{section("Researcher statement", f"<p>{esc(data.get('researcher_statement', 'I reviewed the recorded assessment results and separated confirmed findings from potential leads.'))}</p>")}
{section("Assessment methodology and authorization", "".join(f"<h3>{esc(item['title'])}</h3><p>{esc(item['description'])}</p>" for item in data["methodology"]))}
{section("Executive summary", f"<div class='metrics'>{summary}</div>")}
{section("OpenAPI documented-operation assessments", "<p>Documentation-based observations only. Documented operations were not invoked; these indicators do not prove vulnerabilities.</p><table><tr><th>Check</th><th>Method</th><th>Path</th><th>Operation ID</th><th>Security status</th><th>Identity parameters</th><th>Sensitive parameter names</th><th>Indicators</th><th>Asset</th><th>Recorded</th></tr>" + openapi_rows + "</table>")}
{section("Website scan results", scan_html)}\n{section("Scope assets", f"<table><tr><th>Host</th><th>Included</th><th>Approved</th><th>Notes</th></tr>{assets}</table>")}
{section("Assessment Coverage", coverage_html)}
{section("Findings", findings)}
{section("Assessment checks", f"<table><tr><th>Check</th><th>Outcome</th><th>Asset</th><th>Details</th></tr>{rows(data['checks'], ['check','outcome','asset','details'])}</table>")}
{section("Attack surface", f"<table><tr><th>Method</th><th>URL</th><th>Type</th><th>Notes</th></tr>{rows(data['endpoints'], ['method','url','type','notes'])}</table>")}
{section("Manual test plan", f"<table><tr><th>Category</th><th>Test</th><th>Status</th><th>Target</th><th>Worksheet and instructions</th><th>Assessment result</th></tr>{test_plan_rows}</table>")}
{section("Evidence integrity audit", f"<p>Total: {data['evidence_audit']['summary']['total']} | Verified: {data['evidence_audit']['summary']['verified']} | Missing: {data['evidence_audit']['summary']['missing']} | Invalid paths: {data['evidence_audit']['summary']['invalid_path']} | Size mismatches: {data['evidence_audit']['summary']['size_mismatch']} | SHA-256 mismatches: {data['evidence_audit']['summary']['hash_mismatch']} | Broken links: {data['evidence_audit']['summary']['broken_reference']} | Unlinked: {data['evidence_audit']['summary']['unlinked']}</p><p>Read-only audit; a mismatch is not proof of malicious alteration.</p>")}
{section("Evidence register", f"<table><tr><th>ID</th><th>File</th><th>Finding</th><th>Related findings</th><th>Assessment</th><th>Observation</th><th>Check name</th><th>Outcome</th><th>Asset</th><th>Observed at</th><th>Size (bytes)</th><th>File integrity</th><th>Reference integrity</th><th>SHA-256</th><th>Notes</th></tr>{rows(data['evidence'], ['id','name','finding_id','related_finding_ids','test_case_id','scan_check_id','scan_check_name','scan_check_outcome','scan_check_asset','scan_check_observed_at','size_bytes','file_integrity','reference_integrity','sha256','notes'])}</table>")}
{section("Assessment jobs", f"<table><tr><th>ID</th><th>Type</th><th>Status</th><th>Progress</th><th>Summary</th></tr>{rows(data['jobs'], ['id','type','status','progress','result_summary'])}</table>")}
{section("Activity timeline", f"<table><tr><th>Time</th><th>Event</th><th>Details</th></tr>{rows(data['timeline'], ['at','event','details'])}</table>")}
        {section("Project intelligence", _project_intelligence_html(data, esc))}
{section("Limitations", f"<p>{esc(data['assessment_note'])}</p>")}
<footer><p>Generated locally by BugHunter AI. Handle this report and its evidence as sensitive security information.</p></footer>
</main></body></html>"""


def _pdf_report(data, path):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        KeepTogether,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportSubtitle", parent=styles["Normal"],
        alignment=TA_CENTER, textColor=colors.HexColor("#52657d"),
    ))
    styles.add(ParagraphStyle(
        name="SmallNote", parent=styles["Normal"],
        fontSize=8, leading=11, textColor=colors.HexColor("#52657d"),
    ))

    def para(value, style="BodyText"):
        value = escape(str(value if value is not None else ""))
        value = value.replace("\n", "<br/>")
        return Paragraph(value or " ", styles[style])

    story = [
        Spacer(1, 18 * mm),
        para("BUGHUNTER AI", "Title"),
        para("Security Assessment Report", "ReportSubtitle"),
        Spacer(1, 5 * mm),
        para(data["project"]["name"], "Heading1"),
        para(f"Generated: {data['generated_at']}"),
        para(f"Programme: {data['project']['programme_url']}"),
        para(f"Scope approval recorded: {data['project']['scope_approved']}"),
        para(data.get(
            "researcher_statement",
            "I reviewed the recorded assessment results and distinguish confirmed findings from potential leads and incomplete checks.",
        )),
        Spacer(1, 8 * mm),
        para("Assessment Methodology and Authorization", "Heading1"),
    ]

    for item in data["methodology"]:
        story.append(para(item["title"], "Heading3"))
        story.append(para(item["description"]))

    story += [
        Spacer(1, 5 * mm),
        para("Executive Summary", "Heading1"),
    ]

    counts = data["counts"]
    summary_rows = [
        ["Metric", "Recorded"],
        ["Findings", str(counts["findings"])],
        ["Confirmed findings", str(counts["confirmed"])],
        ["Potential findings", str(counts["potential"])],
        ["Needs review", str(counts["needs_review"])],
        ["Rejected findings", str(counts["rejected"])],
        ["Resolved findings", str(counts["resolved"])],
        ["Critical severity", str(counts["critical"])],
        ["High severity", str(counts["high"])],
        ["Medium severity", str(counts["medium"])],
        ["Low severity", str(counts["low"])],
        ["Informational severity", str(counts["info"])],
        ["Assessment checks", str(counts["checks"])],
        ["Endpoints", str(counts["endpoints"])],
        ["Evidence records", str(counts["evidence"])],
        ["Test-plan entries", str(counts["test_cases"])],
        ["Assessment jobs", str(counts["jobs"])],
        ["Validation: supported observations (not confirmed)", str(counts["validation_supported"])],
        ["Validation: needs manual review", str(counts["validation_manual_review"])],
        ["Validation: insufficient evidence", str(counts["validation_insufficient"])],
        ["Validation: not yet run", str(counts["validation_not_run"])],
        ["OpenAPI assessment observations", str(counts["openapi_assessments"])],
        ["OpenAPI security not declared", str(counts["openapi_security_not_declared"])],
        ["OpenAPI security explicitly empty", str(counts["openapi_security_explicitly_empty"])],
        ["OpenAPI identity parameter assessments", str(counts["openapi_identity_parameter_assessments"])],
        ["OpenAPI sensitive parameter assessments", str(counts["openapi_sensitive_parameter_assessments"])],
        ["OpenAPI write-operation assessments", str(counts["openapi_write_operation_assessments"])],
        ["OpenAPI manual review required", str(counts["openapi_manual_review_required"])],
    ]
    summary_table = Table(summary_rows, colWidths=[85 * mm, 55 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [summary_table, Spacer(1, 5 * mm)]
    story.append(para("OpenAPI Documented-Operation Assessments", "Heading1"))
    story.append(para(
        "Documentation-based observations only. Documented operations were "
        "not invoked; these indicators do not prove vulnerabilities."
    ))
    openapi_pdf_rows = [[
        "Check", "Method", "Documented path", "Operation ID",
        "Security status", "Indicators / parameter names",
    ]]
    for item in data.get("openapi_assessments", []):
        detail_text = (
            "Indicators: " + "; ".join(item["indicators"])
            + " | Identity: " + ", ".join(item["identity_parameter_names"])
            + " | Sensitive names: " + ", ".join(item["sensitive_parameter_names"])
            + " | Asset: " + item["asset"]
            + " | Recorded: " + item["created_at"]
        )
        openapi_pdf_rows.append([
            para(str(item["check_id"])),
            para(item["method"]),
            para(item["documented_path"]),
            para(item["operation_id"]),
            para(item["security_status"]),
            para(detail_text),
        ])
    if len(openapi_pdf_rows) == 1:
        openapi_pdf_rows.append([para("No OpenAPI assessments recorded.")] + [""] * 5)
    openapi_pdf_table = Table(
        openapi_pdf_rows,
        colWidths=[12 * mm, 15 * mm, 38 * mm, 25 * mm, 25 * mm, 55 * mm],
        repeatRows=1,
    )
    openapi_pdf_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [openapi_pdf_table, Spacer(1, 8 * mm), para("Website Scan Results", "Heading1")]
    if not data.get("scan_runs"):
        story.append(para("No website scan runs recorded."))
    for run in data["scan_runs"]:
        story.append(para(f"{run['event']} — {run['at']}", "Heading2"))
        metric_rows = [["Metric", "Recorded"]]
        metric_rows.extend([
            [key.replace("_", " ").capitalize(), str(value)]
            for key, value in run["metrics"].items()
        ])
        metric_table = Table(metric_rows, colWidths=[85 * mm, 55 * mm], repeatRows=1)
        metric_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story += [metric_table, Spacer(1, 5 * mm)]

    story.append(para("Scope Assets", "Heading1"))

    for asset in data["assets"]:
        story.append(para(
            f"{asset['host']} — included: {asset['included']}; "
            f"approved: {asset['approved']}; {asset['notes']}"
        ))
    if not data["assets"]:
        story.append(para("No assets registered."))

    coverage = data["coverage"]
    cs = coverage["summary"]

    story += [
        Spacer(1, 5 * mm),
        para("Assessment Coverage", "Heading1"),
        para(
            f"Approved assets: {cs['approved_assets']} | "
            f"Assessed: {cs['assessed_assets']} | "
            f"Not assessed: {cs['unassessed_assets']} | "
            f"Recorded coverage: {cs['asset_coverage_percent']}%"
        ),
        para(
            f"Assessment checks: {cs['assessment_checks_recorded']} | "
            f"Endpoints: {cs['endpoints_discovered']} | "
            f"Findings: {cs['findings_recorded']}"
        ),
    ]

    category_rows = [[
        para("Category", "SmallNote"),
        para("Done / applicable", "SmallNote"),
        para("Progress", "SmallNote"),
        para("Status", "SmallNote"),
        para("Review", "SmallNote"),
        para("Blocked", "SmallNote"),
    ]]

    for item in coverage["test_plan"]:
        category_rows.append([
            para(item["category"], "SmallNote"),
            para(
                f"{item['completed']} / {item['applicable']}",
                "SmallNote",
            ),
            para(f"{item['completion_percent']}%", "SmallNote"),
            para(item["status"], "SmallNote"),
            para(str(item["needs_review"]), "SmallNote"),
            para(str(item["blocked"]), "SmallNote"),
        ])

    if len(category_rows) == 1:
        category_rows.append([
            para("No test plan initialized", "SmallNote"),
            para("-", "SmallNote"),
            para("-", "SmallNote"),
            para("-", "SmallNote"),
            para("0", "SmallNote"),
            para("0", "SmallNote"),
        ])

    category_table = Table(
        category_rows,
        colWidths=[42 * mm, 32 * mm, 22 * mm, 34 * mm, 18 * mm, 18 * mm],
        repeatRows=1,
        splitByRow=1,
    )
    category_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))

    story += [
        para(
            f"Test plan: {cs['test_cases_completed']} completed / "
            f"{cs['test_cases_total']} total; "
            f"{cs['test_plan_completion_percent']}% completion; "
            f"{cs['unassigned_test_cases']} unassigned.",
            "SmallNote",
        ),
        category_table,
        Spacer(1, 4 * mm),
    ]

    asset_category_rows = [[
        para("Asset", "SmallNote"),
        para("Category", "SmallNote"),
        para("Done / applicable", "SmallNote"),
        para("Progress", "SmallNote"),
        para("Status", "SmallNote"),
        para("Review", "SmallNote"),
        para("Blocked", "SmallNote"),
    ]]

    for asset in coverage["assets"]:
        if not asset["test_categories"]:
            asset_category_rows.append([
                para(asset["host"], "SmallNote"),
                para("No assigned tests", "SmallNote"),
                para("-", "SmallNote"),
                para("-", "SmallNote"),
                para("Not planned", "SmallNote"),
                para("0", "SmallNote"),
                para("0", "SmallNote"),
            ])
            continue

        for item in asset["test_categories"]:
            asset_category_rows.append([
                para(asset["host"], "SmallNote"),
                para(item["category"], "SmallNote"),
                para(
                    f"{item['completed']} / {item['applicable']}",
                    "SmallNote",
                ),
                para(f"{item['completion_percent']}%", "SmallNote"),
                para(item["status"], "SmallNote"),
                para(str(item["needs_review"]), "SmallNote"),
                para(str(item["blocked"]), "SmallNote"),
            ])

    if len(asset_category_rows) == 1:
        asset_category_rows.append([
            para("No approved assets", "SmallNote"),
            para("-", "SmallNote"),
            para("-", "SmallNote"),
            para("-", "SmallNote"),
            para("-", "SmallNote"),
            para("0", "SmallNote"),
            para("0", "SmallNote"),
        ])

    asset_category_table = Table(
        asset_category_rows,
        colWidths=[
            34 * mm, 34 * mm, 27 * mm, 19 * mm,
            29 * mm, 13 * mm, 13 * mm,
        ],
        repeatRows=1,
        splitByRow=1,
    )
    asset_category_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))

    story += [
        para("Per-asset vulnerability-category coverage", "Heading2"),
        asset_category_table,
        Spacer(1, 4 * mm),
    ]

    coverage_rows = [[
        para("Asset", "SmallNote"),
        para("Status", "SmallNote"),
        para("Checks", "SmallNote"),
        para("Endpoints", "SmallNote"),
        para("Findings", "SmallNote"),
        para("Last check", "SmallNote"),
    ]]

    for asset in coverage["assets"]:
        coverage_rows.append([
            para(asset["host"], "SmallNote"),
            para(asset["assessment_status"], "SmallNote"),
            para(str(asset["checks_completed"]), "SmallNote"),
            para(str(asset["endpoints_discovered"]), "SmallNote"),
            para(str(asset["findings_recorded"]), "SmallNote"),
            para(asset["last_check"] or "Never", "SmallNote"),
        ])

    if len(coverage_rows) == 1:
        coverage_rows.append([
            para("No approved assets", "SmallNote"),
            para("-", "SmallNote"),
            para("0", "SmallNote"),
            para("0", "SmallNote"),
            para("0", "SmallNote"),
            para("Never", "SmallNote"),
        ])

    coverage_table = Table(
        coverage_rows,
        colWidths=[42 * mm, 25 * mm, 18 * mm, 20 * mm, 20 * mm, 39 * mm],
        repeatRows=1,
        splitByRow=1,
    )
    coverage_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))

    story += [
        coverage_table,
        Spacer(1, 3 * mm),
        para(coverage["notice"], "SmallNote"),
        Spacer(1, 5 * mm),
        para("Findings", "Heading1"),
    ]
    if not data["findings"]:
        story.append(para("No findings recorded."))

    for f in data["findings"]:
        block = [
            para(f"#{f['id']} — {f['title']}", "Heading2"),
            para(
                f"Severity: {f['severity']} | Confidence: {f['confidence']} | "
                f"Status: {f['status']} | Category: {f['category']}"
            ),
            para(f"Asset: {f['asset'] or 'Not recorded'}"),
            para("Automated validation — not a confirmation", "Heading3"),
            para(
                f"Classification: {f['validation']['classification']} | "
                f"Family: {f['validation']['family']}"
            ),
            para(
                f"Indicators: {', '.join(f['validation']['indicator_names']) or 'None recorded'}"
            ),
            para(
                f"Rationale: {f['validation']['rationale'] or 'Not recorded'}"
            ),
            para(
                "Source check IDs: "
                + (
                    ", ".join(
                        str(value)
                        for value in f["validation"].get("source_check_ids", [])
                    )
                    or "None recorded"
                )
            ),
            *[
                para("Source observation: " + line)
                for line in _validation_source_lines(f["validation"])
            ],
            para("Automatically confirmed: No | Manual review required: Yes"),
            para("Description", "Heading3"),
            para(f["description"]),
            para("Evidence and observations", "Heading3"),
            para(f["evidence"]),
            para("Attached evidence files", "Heading3"),
            para(
                "\\n".join(
                    f"Evidence #{e['id']}: {e['name']} | "
                    f"Finding: #{e['finding_id'] or 'none'} | "
                    f"Assessment: #{e['test_case_id'] or 'none'} | "
                    f"Observation: #{e['scan_check_id'] or 'none'} | "
                    f"Check: {e.get('scan_check_name') or 'Unknown check'} | "
                    f"Outcome: {e.get('scan_check_outcome') or 'unknown'} | "
                    f"Asset: {e.get('scan_check_asset') or 'Not recorded'} | "
                    f"Observed: {e.get('scan_check_observed_at') or 'Not recorded'} | "
                    f"Relationship: {e.get('finding_link_basis', 'linked evidence')} | "
                    f"SHA-256: {e['sha256']} | {e['size_bytes']} bytes"
                    for e in f["evidence_files"]
                ) or "No files linked to this finding."
            ),
            para("Remediation", "Heading3"),
            para(f["remediation"]),
            para("Review history", "Heading3"),
            para(
                "\\n".join(
                    (
                        f"Review #{r['id']} — {r['created_at']}\\n"
                        f"Reviewer: {r['reviewer']}\\n"
                        f"Status: {r['previous_status']} -> {r['new_status']}\\n"
                        f"Severity: {r['previous_severity']} -> {r['new_severity']}\\n"
                        f"Confidence: {r['previous_confidence']} -> {r['new_confidence']}\\n"
                        f"Notes: {r['notes'] or 'None'}"
                    )
                    for r in f["review_history"]
                ) or "No structured review history recorded."
            ),
            Spacer(1, 4 * mm),
        ]
        # Let long findings split naturally across PDF pages.
        story.extend(block)

    sections = [
        ("Assessment Checks", data["checks"], ["check", "outcome", "asset", "details"]),
        ("Endpoint Assessment Coverage", data["coverage"]["endpoints"], [
            "url", "classification", "priority_band", "priority_score",
            "signals_summary", "status", "completed", "total", "needs_review"
        ]),
        ("API Resource Relationship Map",
         data["coverage"].get("api_resource_groups", []), [
             "resource_path", "methods", "endpoint_count",
             "assessment_summary", "authorization_summary",
             "identifier_parameters", "authorization_review_signals",
             "parent_resource", "not_observed"
         ]),
        ("Vulnerability-Specific Assessment Scenarios",
         data["coverage"].get("assessment_scenarios", []), [
             "category", "title", "method", "target",
             "review_priority", "status", "trigger",
             "safe_steps", "evidence_to_record"
         ]),
        ("Attack Surface", data["endpoints"], ["method", "url", "type", "notes"]),
        ("Manual Test Plan", data["test_plan"], [
            "category", "title", "status", "target",
            "worksheet", "assessment_result"
        ]),
        ("Evidence Register", data["evidence"], [
            "id", "name", "finding_id", "related_finding_ids",
            "test_case_id", "scan_check_id", "scan_check_name",
            "scan_check_outcome", "scan_check_asset",
            "scan_check_observed_at", "size_bytes",
            "file_integrity", "reference_integrity",
            "actual_size_bytes", "file_reason", "reference_reason",
            "sha256", "notes"
        ]),
        ("Assessment Jobs", data["jobs"], ["id", "type", "status", "progress", "result_summary"]),
        ("Activity Timeline", data["timeline"], ["at", "event", "details"]),
    ]

    for title, records, fields in sections:
        story += [para(title, "Heading1")]
        if not records:
            story.append(para("No records."))
            continue

        # Long worksheets and assessment results must flow across pages.
        # A ReportLab table cannot split an individual oversized row.
        if title == "Manual Test Plan":
            for index, record in enumerate(records, 1):
                story.append(para(
                    f"{index}. {record.get('title') or 'Untitled assessment'}",
                    "Heading3",
                ))
                story.append(para(
                    "Category: " + str(record.get("category") or "Not recorded")
                    + " | Status: " + str(record.get("status") or "Not recorded")
                ))
                story.append(para(
                    "Target: " + str(record.get("target") or "Not recorded")
                ))
                for field in ("worksheet", "assessment_result"):
                    value = record.get(field)
                    if value not in (None, "", [], {}):
                        story.append(para(
                            field.replace("_", " ").title() + ": " + str(value)
                        ))
                story.append(Spacer(1, 2 * mm))
            story.append(Spacer(1, 3 * mm))
            continue

        rows_data = [[para(field.replace("_", " ").title(), "SmallNote") for field in fields]]
        for record in records:
            rows_data.append([para(record.get(field, ""), "SmallNote") for field in fields])

        usable_width = A4[0] - (36 * mm)
        column_width = usable_width / max(1, len(fields))
        table = Table(
            rows_data,
            colWidths=[column_width] * len(fields),
            repeatRows=1,
            hAlign="LEFT",
            splitByRow=1,
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story += [table, Spacer(1, 5 * mm)]

    _project_intelligence_pdf(data, para, story, colors, Table, TableStyle, Spacer, mm)
    story += [
        para("Limitations", "Heading1"),
        para(data["assessment_note"]),
        Spacer(1, 5 * mm),
        para(
            "Generated locally by BugHunter AI. Treat this report and its "
            "evidence as sensitive security information.",
            "SmallNote",
        ),
    ]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, "BugHunter AI — Confidential security research")
        canvas.drawRightString(192 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(path), pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"BugHunter AI Report — {data['project']['name']}",
        author="BugHunter AI",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)



def _docx_report(data, path):
    """Create an editable Word report using the complete Markdown report."""
    import re
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor

    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)

    styles = document.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(9)
    styles["Title"].font.name = "Arial"
    styles["Title"].font.color.rgb = RGBColor(20, 75, 130)

    project_name = data.get("project", {}).get("name", "Security Assessment")
    document.core_properties.title = f"BugHunter AI Report - {project_name}"
    document.core_properties.author = "BugHunter AI"
    document.core_properties.subject = "Security Assessment Report"

    header = section.header.paragraphs[0]
    header.text = "BUGHUNTER AI  |  SECURITY ASSESSMENT"
    header.style = "Caption"

    footer = section.footer.paragraphs[0]
    footer.text = "Confidential security information — handle and share responsibly"
    footer.style = "Caption"

    markdown = _markdown(data)
    if not isinstance(markdown, str):
        markdown = str(markdown)

    lines = markdown.splitlines()
    index = 0

    def clean_inline(value):
        value = re.sub(r'!\[([^\]]*)\]\([^)]+\)', r'\1', value)
        value = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'\1 (\2)', value)
        value = re.sub(r'`([^`]*)`', r'\1', value)
        value = value.replace("**", "").replace("__", "")
        value = value.replace("~~", "").replace("*", "")
        return value.strip()

    while index < len(lines):
        raw = lines[index].strip()

        if not raw:
            index += 1
            continue

        # Markdown tables
        if raw.startswith("|") and index + 1 < len(lines) and "---" in lines[index + 1]:
            table_lines = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1

            rows = []
            for row in table_lines:
                cells = [clean_inline(c.strip()) for c in row.strip("|").split("|")]
                if cells and not all(re.fullmatch(r":?-{2,}:?", c or "") for c in cells):
                    rows.append(cells)

            if rows:
                columns = max(len(row) for row in rows)
                table = document.add_table(rows=0, cols=columns)
                table.style = "Light Shading Accent 1"
                for row_number, values in enumerate(rows):
                    cells = table.add_row().cells
                    for col_number in range(columns):
                        value = values[col_number] if col_number < len(values) else ""
                        cells[col_number].text = value
                        if row_number == 0:
                            for run in cells[col_number].paragraphs[0].runs:
                                run.bold = True
            continue

        heading = re.match(r"^(#{1,4})\s+(.*)$", raw)
        if heading:
            level = min(len(heading.group(1)), 3)
            text_value = clean_inline(heading.group(2))
            if level == 1:
                document.add_heading(text_value, level=0)
            else:
                document.add_heading(text_value, level=level)
            index += 1
            continue

        if raw in ("---", "***", "___"):
            document.add_paragraph()
            index += 1
            continue

        if re.match(r"^[-*+]\s+", raw):
            value = clean_inline(re.sub(r"^[-*+]\s+", "", raw))
            document.add_paragraph(value, style="List Bullet")
            index += 1
            continue

        if re.match(r"^\d+[.)]\s+", raw):
            value = clean_inline(re.sub(r"^\d+[.)]\s+", "", raw))
            document.add_paragraph(value, style="List Number")
            index += 1
            continue

        if raw.startswith(">"):
            paragraph = document.add_paragraph(style="Quote")
            paragraph.add_run(clean_inline(raw.lstrip("> ")))
            index += 1
            continue

        if raw.startswith("```"):
            index += 1
            code_lines = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            paragraph = document.add_paragraph()
            run = paragraph.add_run("\n".join(code_lines))
            run.font.name = "Consolas"
            run.font.size = Pt(8)
            continue

        document.add_paragraph(clean_inline(raw))
        index += 1

    document.save(str(path))

def export_report(db, pid, destination, fmt):
    data = report_data(db, pid)

    data["counts"].update({
        "findings": len(data["findings"]),
        "confirmed": sum(f["status"].lower() == "confirmed" for f in data["findings"]),
        "potential": sum(f["status"].lower() == "potential" for f in data["findings"]),
        "needs_review": sum(f["status"].lower() == "needs_review" for f in data["findings"]),
        "rejected": sum(f["status"].lower() == "rejected" for f in data["findings"]),
        "resolved": sum(f["status"].lower() == "resolved" for f in data["findings"]),
        "critical": sum(f["severity"].lower() == "critical" for f in data["findings"]),
        "high": sum(f["severity"].lower() == "high" for f in data["findings"]),
        "medium": sum(f["severity"].lower() == "medium" for f in data["findings"]),
        "low": sum(f["severity"].lower() == "low" for f in data["findings"]),
        "info": sum(f["severity"].lower() in ("info", "informational") for f in data["findings"]),
        "checks": len(data["checks"]),
        "endpoints": len(data["endpoints"]),
        "evidence": len(data["evidence"]),
        "test_cases": len(data["test_plan"]),
        "jobs": len(data["jobs"]),
        "validation_supported": data["counts"]["validation_supported"],
        "validation_manual_review": data["counts"]["validation_manual_review"],
        "validation_insufficient": data["counts"]["validation_insufficient"],
        "validation_not_run": data["counts"]["validation_not_run"],
    })

    hunt_jobs = [
        job for job in data.get("jobs", [])
        if job.get("type") == "Automated hunt"
    ]
    if hunt_jobs and all(job.get("status") == "completed" for job in hunt_jobs):
        completion_sentence = "I completed the queued automated hunt jobs."
    elif hunt_jobs:
        completion_sentence = (
            "I reviewed the results available when the automated hunt jobs ended; "
            "some jobs did not complete successfully, so the coverage below is partial."
        )
    else:
        completion_sentence = "I reviewed the assessment records currently stored for this project."

    data["researcher_statement"] = (
        "I conducted this authorized-scope assessment using the programme policy "
        "snapshot and exact assets approved for this project. "
        + completion_sentence
        + f" I recorded {len(data['findings'])} finding(s), including "
        + f"{sum(f['status'].lower() == 'confirmed' for f in data['findings'])} "
        + "marked confirmed and "
        + f"{sum(f['status'].lower() in {'potential', 'needs_review'} for f in data['findings'])} "
        + "still requiring review. I have not treated a heuristic, endpoint inventory "
        "or response difference by itself as proof of exploitability. I have identified "
        "the assessment limitations and incomplete checks in this report."
    )

    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = fmt.lower().lstrip(".")

    if fmt == "json":
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "markdown":
        path.write_text(_markdown(data), encoding="utf-8")
    elif fmt == "html":
        path.write_text(_html_report(data), encoding="utf-8")
    elif fmt == "pdf":
        _pdf_report(data, path)
    elif fmt in ("docx", "word"):
        _docx_report(data, path)
    else:
        raise ValueError(
            "Unsupported format. Choose JSON, Markdown, HTML, PDF or DOCX."
        )

    return path


def _load_project_intelligence(db, pid):
    """Load read-only project intelligence for report exports."""
    try:
        from app.services.project_intelligence import get_project_intelligence
        return get_project_intelligence(db, pid)
    except Exception as exc:
        return {"error": str(exc)}


def _project_intelligence_markdown(data):
    intelligence = data.get("project_intelligence") or {}
    if intelligence.get("error"):
        return [
            "", "## Project intelligence",
            "Intelligence unavailable: " + str(intelligence["error"]), ""
        ]

    inventory = intelligence.get("inventory", {})
    assessment = intelligence.get("assessment", {})
    summary = assessment.get("summary", {})
    findings = intelligence.get("finding_summary", {})
    resources = intelligence.get("resource_summary", {})
    duplicates = intelligence.get("duplicate_review", {})
    integrity = intelligence.get("integrity", {})

    result = [
        "", "## Project intelligence", "",
        "### Inventory",
        f"- Endpoints: {inventory.get('endpoints', 0)}",
        f"- Test cases: {inventory.get('test_cases', 0)}",
        f"- Findings: {inventory.get('findings', 0)}",
        "", "### Assessment progress",
        f"- Recommendations: {summary.get('recommendations', 0)}",
        f"- Completed: {summary.get('completed', 0)}",
        f"- Completion: {summary.get('completion_percent', 0)}%",
        "", "### API resource coverage",
        f"- Resource groups: {resources.get('resource_groups', 0)}",
        f"- API resource endpoints: {resources.get('api_resource_endpoints', 0)}",
        "", "### Finding review",
        f"- Potential findings: {findings.get('potential', 0)}",
        f"- Confirmed or verified: {findings.get('confirmed_or_verified', 0)}",
        f"- Exact duplicate groups: {duplicates.get('exact_group_count', 0)}",
        f"- Possible duplicate pairs: {duplicates.get('possible_pair_count', 0)}",
        "", "### Endpoint recommendations",
    ]

    endpoints = assessment.get("endpoints", [])
    if not endpoints:
        result.append("No endpoint recommendations recorded.")

    for endpoint in endpoints:
        result.append(
            f"- {endpoint.get('method', 'GET')} {endpoint.get('url', '')} "
            f"— {endpoint.get('priority_band', 'Unclassified')} priority"
        )
        for item in endpoint.get("recommendations", []):
            result.append(
                f"  - [{item.get('status', 'Planned')}] "
                f"{item.get('category', 'General')}: "
                f"{item.get('title', 'Assessment task')}"
            )

    result += [
        "", "### Integrity and safety",
        f"- Read-only analysis: {integrity.get('read_only', False)}",
        f"- Automatic finding confirmation: {integrity.get('automatic_finding_confirmation', False)}",
        f"- Automatic duplicate merges: {integrity.get('automatic_duplicate_merges', 0)}",
        f"- Planner network requests: {integrity.get('network_requests_made', 0)}",
        f"- Planner payloads executed: {integrity.get('payloads_executed', 0)}",
        "- Human review is required for potential findings and duplicate suggestions.",
        "",
    ]
    return result


def _project_intelligence_html(data, esc):
    intelligence = data.get("project_intelligence") or {}
    if intelligence.get("error"):
        return "<p>Intelligence unavailable: " + esc(intelligence["error"]) + "</p>"

    inventory = intelligence.get("inventory", {})
    assessment = intelligence.get("assessment", {})
    summary = assessment.get("summary", {})
    findings = intelligence.get("finding_summary", {})
    resources = intelligence.get("resource_summary", {})
    duplicates = intelligence.get("duplicate_review", {})

    metrics = [
        ("Endpoints", inventory.get("endpoints", 0)),
        ("Test cases", inventory.get("test_cases", 0)),
        ("Findings", inventory.get("findings", 0)),
        ("Recommendations", summary.get("recommendations", 0)),
        ("Completed", summary.get("completed", 0)),
        ("Completion", str(summary.get("completion_percent", 0)) + "%"),
        ("API resource groups", resources.get("resource_groups", 0)),
        ("Potential findings", findings.get("potential", 0)),
        ("Confirmed / verified", findings.get("confirmed_or_verified", 0)),
        ("Exact duplicate groups", duplicates.get("exact_group_count", 0)),
        ("Possible duplicate pairs", duplicates.get("possible_pair_count", 0)),
    ]

    rows = "".join(
        "<tr><th>" + esc(k) + "</th><td>" + esc(v) + "</td></tr>"
        for k, v in metrics
    )

    endpoint_rows = []
    for endpoint in assessment.get("endpoints", []):
        endpoint_rows.append(
            "<tr><td>" + esc(endpoint.get("method", "GET")) +
            "</td><td>" + esc(endpoint.get("url", "")) +
            "</td><td>" + esc(endpoint.get("priority_band", "Unclassified")) +
            "</td></tr>"
        )

    if not endpoint_rows:
        endpoint_rows.append(
            "<tr><td colspan='3'>No endpoint recommendations recorded</td></tr>"
        )

    return (
        "<h3>Project intelligence</h3>"
        "<table><tr><th>Metric</th><th>Value</th></tr>" + rows + "</table>"
        "<h3>Endpoint recommendations</h3>"
        "<table><tr><th>Method</th><th>Endpoint</th><th>Priority</th></tr>"
        + "".join(endpoint_rows) + "</table>"
        "<p>Potential findings and duplicate suggestions require human review.</p>"
    )


def _project_intelligence_pdf(data, para, story, colors, Table, TableStyle, Spacer, mm):
    intelligence = data.get("project_intelligence") or {}
    story.append(para("Project intelligence", "Heading1"))

    if intelligence.get("error"):
        story.append(para("Intelligence unavailable: " + str(intelligence["error"])))
        return

    inventory = intelligence.get("inventory", {})
    assessment = intelligence.get("assessment", {})
    summary = assessment.get("summary", {})
    findings = intelligence.get("finding_summary", {})
    resources = intelligence.get("resource_summary", {})
    duplicates = intelligence.get("duplicate_review", {})

    values = [
        ["Metric", "Value"],
        ["Endpoints", inventory.get("endpoints", 0)],
        ["Test cases", inventory.get("test_cases", 0)],
        ["Findings", inventory.get("findings", 0)],
        ["Recommendations", summary.get("recommendations", 0)],
        ["Completed", summary.get("completed", 0)],
        ["Completion", str(summary.get("completion_percent", 0)) + "%"],
        ["API resource groups", resources.get("resource_groups", 0)],
        ["Potential findings", findings.get("potential", 0)],
        ["Confirmed / verified", findings.get("confirmed_or_verified", 0)],
        ["Exact duplicate groups", duplicates.get("exact_group_count", 0)],
        ["Possible duplicate pairs", duplicates.get("possible_pair_count", 0)],
    ]

    table = Table(
        [[para(str(cell), "SmallNote") for cell in row] for row in values],
        colWidths=[65 * mm, 105 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Spacer(1, 4 * mm)])

    story.append(para("Endpoint recommendations", "Heading2"))
    for endpoint in assessment.get("endpoints", []):
        story.append(para(
            f"{endpoint.get('method', 'GET')} {endpoint.get('url', '')} — "
            f"{endpoint.get('priority_band', 'Unclassified')} priority"
        ))
        for item in endpoint.get("recommendations", []):
            story.append(para(
                f"[{item.get('status', 'Planned')}] "
                f"{item.get('category', 'General')}: "
                f"{item.get('title', 'Assessment task')}"
            ))

    story.append(para(
        "Potential findings and duplicate suggestions require human review."
    ))
