"""Conservative, database-only validation of potential scanner findings.

This service does not make network requests, execute payloads, or confirm
vulnerabilities. It correlates existing passive ScanCheck observations.
"""

import json
import re

from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services.projects import require_active_project


VALIDATION_CHECK_NAME = "Automated finding validation"

FAMILY_RULES = {
    "transport": {
        "finding_terms": (
            "mixed-content", "insecure http form",
            "insecure resource", "http form submission",
        ),
        "checks": ("HTML transport, form, metadata, and debug review",),
        "markers": ("insecure_resource_count", "insecure_form_count"),
    },
    "cors": {
        "finding_terms": ("cors", "cross-origin", "cross origin"),
        "checks": ("CORS response policy",),
        "markers": (
            "origin_match",
            "reflected_origin",
            "credentialed_origin",
            "allow_origin",
            "allow_credentials",
            "credentials_enabled",
        ),
    },
    "headers": {
        "finding_terms": (
            "security header", "hsts", "content security policy",
            "csp", "clickjacking", "frame options",
        ),
        "checks": (
            "CSP and HSTS policy review",
            "Automated website response analysis",
        ),
        "markers": ("missing_security_headers", "hsts", "csp"),
    },
    "csrf": {
        "finding_terms": ("csrf", "cross-site request forgery"),
        "checks": ("HTML transport, form, metadata, and debug review",),
        "markers": ("csrf_candidate_forms", "csrf_missing_forms", "forms_missing_csrf"),
    },
    "sql": {
        "finding_terms": ("sql", "database error", "injection"),
        "checks": ("HTML transport, form, metadata, and debug review",),
        "markers": ("sql_error_indicator_count", "sql_error_indicators", "sql_error_matches", "database_errors"),
    },
    "client": {
        "finding_terms": (
            "javascript", "dom", "innerhtml", "outerhtml", "postmessage",
            "eval(", "client-side", "client side",
        ),
        "checks": ("Static JavaScript security pattern review",),
        "markers": ("potential_patterns", "unsafe_sinks", "dangerous_functions"),
    },
    "xss": {
        "finding_terms": ("xss", "cross-site scripting", "reflected html input"),
        "checks": ("Query parameter reflection review",),
        "markers": ("unescaped_reflected_parameter_names",),
    },
    "open_redirect": {
        "finding_terms": (
            "open redirect", "redirect to an external origin",
            "redirect destination",
        ),
        "checks": ("Redirect destination review",),
        "markers": ("redirect_parameter_names",),
    },
    "sensitive": {
        "finding_terms": (
            "sensitive", "secret", "credential", "token", "api key",
            "private key", "exposed key",
        ),
        "checks": (
            "Client-side sensitive marker review",
            "Passive API response disclosure review",
        ),
        "markers": (
            "markers", "sensitive_property_names", "sensitive_fields",
            "sensitive_metadata",
        ),
    },
    "errors": {
        "finding_terms": (
            "stack trace", "traceback", "verbose error", "debug information",
            "internal path",
        ),
        "checks": (
            "Passive API response disclosure review",
            "HTML transport, form, metadata, and debug review",
        ),
        "markers": ("verbose_error_indicators", "error_indicators", "debug_matches"),
    },
    "authorization": {
        "finding_terms": (
            "authorization", "cross-account access", "idor",
            "broken object level", "tenant isolation",
        ),
        "checks": (
            "Researcher-owned resource cross-account comparison",
            "Role-based authorization evidence summary",
            "Credentialed API access comparison",
        ),
        "markers": (
            "owner_attested_cross_account_success",
            "role_behavioral_difference_observed",
            "credentialed_response_difference_observed",
        ),
    },
    "ssrf": {
        "finding_terms": (
            "ssrf", "server-side request forgery",
            "server-side url fetch input",
        ),
        "checks": ("OpenAPI documented operation assessment",),
        "markers": (
            "url_input_parameter_names",
            "url_input_body_field_names",
        ),
    },
    "forms": {
        "finding_terms": ("password form", "password over get", "external form", "external origin"),
        "checks": ("HTML transport, form, metadata, and debug review",),
        "markers": ("password_get_form_count", "external_form_count", "password_get_forms", "external_forms"),
    },
}


def _finding_family(finding):
    text = f"{finding.title or ''} {finding.category or ''}".lower()

    for family, rule in FAMILY_RULES.items():
        if any(term in text for term in rule["finding_terms"]):
            return family, rule

    return None, None


def _load_details(raw):
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        return value if isinstance(value, (dict, list)) else {}
    except (ValueError, TypeError):
        return {}


def _walk_for_markers(value, wanted, found=None, depth=0):
    """Return marker names only; never copy observed values into validation."""
    if found is None:
        found = set()
    if depth > 12:
        return found

    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if normalized in wanted:
                positive = False
                if isinstance(child, bool):
                    positive = child
                elif isinstance(child, (list, tuple, set, dict)):
                    positive = len(child) > 0
                elif isinstance(child, (int, float)):
                    positive = child > 0
                elif isinstance(child, str):
                    positive = bool(child.strip())

                if positive:
                    found.add(normalized)

            _walk_for_markers(child, wanted, found, depth + 1)

    elif isinstance(value, list):
        for child in value[:500]:
            _walk_for_markers(child, wanted, found, depth + 1)

    return found


def _matching_checks(family, finding, checks, rule):
    allowed_names = set(rule["checks"])
    if family == "authorization":
        allowed_outcomes = {
            "potential_cross_account_access",
            "cross_account_access_denied",
            "inconclusive",
            "owner_access_not_verified",
            "difference_observed",
            "completed",
        }
    elif family == "open_redirect":
        allowed_outcomes = {"external_redirect_candidate"}
    else:
        allowed_outcomes = {"completed"}
    return [
        check for check in checks
        if check.asset == finding.asset
        and check.check_name in allowed_names
        and check.outcome in allowed_outcomes
    ]


def _collect_validation_markers(family, matched, rule):
    """Collect conservative indicators from completed observations."""
    found = set()
    wanted = set(rule["markers"])

    if family == "authorization":
        for check in matched:
            details = _load_details(check.details)
            if (
                check.outcome == "potential_cross_account_access"
                and isinstance(details, dict)
                and details.get("outcome") == "potential_cross_account_access"
                and details.get("owner_access_attested") is True
                and details.get("vulnerability_confirmed") is False
            ):
                try:
                    requester_status = int(details.get("requester_status"))
                except (TypeError, ValueError):
                    continue
                if 200 <= requester_status < 300:
                    found.add("owner_attested_cross_account_success")
            elif (
                check.check_name == "Role-based authorization evidence summary"
                and isinstance(details, dict)
                and details.get("behavioral_difference_observed") is True
                and details.get("automatically_confirmed") is False
            ):
                found.add("role_behavioral_difference_observed")
            elif (
                check.check_name == "Credentialed API access comparison"
                and isinstance(details, dict)
                and (
                    details.get("status_changed") is True
                    or details.get("sensitive_field_names_changed") is True
                )
            ):
                found.add("credentialed_response_difference_observed")
        return found

    for check in matched:
        details = _load_details(check.details)

        if family == "cors":
            if not isinstance(details, dict):
                continue

            allowed_origin = details.get("allow_origin")
            diagnostic_origin = details.get("diagnostic_origin")
            credentials = details.get("allow_credentials")

            if (
                isinstance(allowed_origin, str)
                and isinstance(diagnostic_origin, str)
                and allowed_origin.strip()
                and allowed_origin.strip() == diagnostic_origin.strip()
                and credentials is True
            ):
                found.add("credentialed_origin_match")

            continue

        found.update(_walk_for_markers(details, wanted))

    return found


def _validation_record(db, finding, classification, family, matched, markers, rationale):
    record = {
        "record_type": "bughunter_validation",
        "finding_id": finding.id,
        "classification": classification,
        "family": family,
        "matched_checks": [
            {
                "check_id": check.id,
                "check_name": check.check_name,
                "outcome": check.outcome,
                "asset": check.asset,
                "observed_at": (
                    check.created_at.isoformat()
                    if check.created_at else None
                ),
            }
            for check in matched
        ],
        "source_check_ids": [
            check.id for check in matched if check.id is not None
        ],
        "source_observations": [
            {
                "check_id": check.id,
                "check_name": check.check_name,
                "outcome": check.outcome,
                "asset": check.asset,
                "observed_at": (
                    check.created_at.isoformat()
                    if check.created_at else None
                ),
            }
            for check in matched[:30]
        ],
        "indicator_names": sorted(markers),
        "rationale": rationale,
        "manual_review_required": True,
        "auto_confirmed": False,
        "network_requests_made": 0,
        "payloads_executed": False,
    }

    serialized = json.dumps(record, ensure_ascii=True)

    # Update the latest record for this finding instead of creating duplicates.
    previous = db.scalars(
        select(ScanCheck)
        .where(
            ScanCheck.project_id == finding.project_id,
            ScanCheck.check_name == VALIDATION_CHECK_NAME,
            ScanCheck.asset == finding.asset,
        )
        .order_by(ScanCheck.id.desc())
    ).all()

    existing = None
    for item in previous:
        old = _load_details(item.details)
        if old.get("record_type") == "bughunter_validation" and old.get("finding_id") == finding.id:
            existing = item
            break

    if existing:
        existing.outcome = classification
        existing.details = serialized
    else:
        db.add(ScanCheck(
            project_id=finding.project_id,
            asset=finding.asset,
            check_name=VALIDATION_CHECK_NAME,
            outcome=classification,
            details=serialized,
        ))


def validate_project_findings(db, project_id):
    """Correlate potential findings with existing checks; never confirm them."""
    project = require_active_project(db, project_id)

    if not project.scope_approved:
        raise ValueError("Project scope must be approved before validation.")

    findings = db.scalars(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.status == "potential",
        )
    ).all()

    checks = db.scalars(
        select(ScanCheck).where(
            ScanCheck.project_id == project_id,
            ScanCheck.check_name != VALIDATION_CHECK_NAME,
        )
    ).all()

    counts = {
        "findings_examined": 0,
        "supported_by_observation": 0,
        "needs_manual_review": 0,
        "insufficient_evidence": 0,
        "findings_changed": 0,
        "network_requests": 0,
        "payloads_executed": 0,
    }

    for finding in findings:
        counts["findings_examined"] += 1
        family, rule = _finding_family(finding)

        if not rule:
            classification = "insufficient_evidence"
            matched = []
            markers = set()
            rationale = (
                "No conservative validation rule matched this finding. "
                "Manual review and reproducible evidence are required."
            )
        else:
            matched = _matching_checks(family, finding, checks, rule)
            markers = _collect_validation_markers(
                family, matched, rule
            )

            if markers:
                classification = "supported_by_observation"
                rationale = (
                    "A related completed passive check recorded one or more "
                    "matching indicator fields. This supports further review "
                    "but does not establish exploitability."
                )
            elif matched:
                classification = "needs_manual_review"
                rationale = (
                    "A related check exists, but no matching positive "
                    "indicator could be safely established from its details."
                )
            else:
                classification = "insufficient_evidence"
                rationale = (
                    "No completed related check was found for this exact asset."
                )

        _validation_record(
            db, finding, classification, family, matched, markers, rationale
        )
        counts[classification] += 1

    db.commit()
    return counts
