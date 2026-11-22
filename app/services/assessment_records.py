"""Structured manual assessment results and audit observations.

This module records reviewer-supplied observations only. It does not perform
network requests, execute payloads, or automatically confirm vulnerabilities.
"""

import json
from datetime import datetime, timezone

from app.models.entities import TestCase, ScanCheck, Finding


VALID_STATUSES = {
    "Planned",
    "In progress",
    "Needs review",
    "Finding identified",
    "Passed",
    "Blocked",
    "Not applicable",
}

RESULT_MARKER = "ASSESSMENT_RESULT_HISTORY:"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean(value, limit=12000):
    return str(value or "").strip()[:limit]


def assessment_history(test_case):
    """Read structured result history without changing existing notes."""
    notes = str(getattr(test_case, "notes", "") or "")
    position = notes.find(RESULT_MARKER)

    if position < 0:
        return []

    raw = notes[position + len(RESULT_MARKER):].strip()
    if not raw:
        return []

    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []

    return value if isinstance(value, list) else []


def _write_history(test_case, history):
    notes = str(getattr(test_case, "notes", "") or "")
    position = notes.find(RESULT_MARKER)

    if position >= 0:
        notes = notes[:position].rstrip()

    serialized = json.dumps(
        history[-100:],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    section = RESULT_MARKER + "\n" + serialized

    test_case.notes = (
        notes + "\n\n" + section if notes.strip() else section
    )


def build_assessment_record(
    test_case,
    status,
    expected_behavior,
    observed_behavior,
    evidence_reference="",
    limitations="",
    reviewer="",
):
    if status not in VALID_STATUSES:
        raise ValueError("Unsupported assessment status.")

    return {
        "recorded_at": _now(),
        "test_case_id": getattr(test_case, "id", None),
        "category": _clean(getattr(test_case, "category", ""), 120),
        "title": _clean(getattr(test_case, "title", ""), 300),
        "target": _clean(getattr(test_case, "target", ""), 2048),
        "status": status,
        "expected_behavior": _clean(expected_behavior),
        "observed_behavior": _clean(observed_behavior),
        "evidence_reference": _clean(evidence_reference, 2048),
        "limitations": _clean(limitations),
        "reviewer": _clean(reviewer, 200),
        "manual_review_required": True,
        "automatically_confirmed": False,
    }


def record_assessment_result(
    db,
    test_case_id,
    status,
    expected_behavior,
    observed_behavior,
    evidence_reference="",
    limitations="",
    reviewer="",
    create_potential_finding=False,
):
    """Record a reviewer-supplied result.

    The caller owns the transaction and must commit or roll back.
    """
    test_case = (
        db.query(TestCase)
        .filter(TestCase.id == test_case_id)
        .first()
    )
    if test_case is None:
        raise ValueError("Assessment test case was not found.")

    record = build_assessment_record(
        test_case,
        status,
        expected_behavior,
        observed_behavior,
        evidence_reference,
        limitations,
        reviewer,
    )

    history = assessment_history(test_case)
    history.append(record)
    _write_history(test_case, history)

    test_case.status = status

    details = {
        "record_type": "manual_assessment_result",
        "test_case_id": test_case.id,
        "status": status,
        "expected_behavior": record["expected_behavior"],
        "observed_behavior": record["observed_behavior"],
        "evidence_reference": record["evidence_reference"],
        "limitations": record["limitations"],
        "reviewer": record["reviewer"],
        "manual_review_required": True,
        "automatically_confirmed": False,
    }

    observation = ScanCheck(
        project_id=test_case.project_id,
        asset=record["target"] or "Unspecified approved endpoint",
        check_name=("Manual assessment: " + record["title"])[:120],
        outcome=status.lower().replace(" ", "_"),
        details=json.dumps(details, ensure_ascii=False),
    )
    db.add(observation)
    db.flush()

    potential_finding = None
    if create_potential_finding:
        if status != "Finding identified":
            raise ValueError(
                "Potential findings can only be created from "
                "'Finding identified' assessments."
            )

        if not record["observed_behavior"]:
            raise ValueError(
                "An observed behavior description is required."
            )

        finding_evidence = {
            "source": "manual_assessment",
            "test_case_id": test_case.id,
            "scan_check_id": observation.id,
            "evidence_reference": record["evidence_reference"],
            "observed_behavior": record["observed_behavior"],
            "expected_behavior": record["expected_behavior"],
            "limitations": record["limitations"],
            "manual_verification_required": True,
        }

        potential_finding = Finding(
            project_id=test_case.project_id,
            title=("Potential: " + record["title"])[:300],
            category=record["category"] or "Manual assessment",
            severity="Informational",
            confidence="low",
            status="potential",
            asset=record["target"] or "Unspecified endpoint",
            description=(
                "Reviewer-recorded observation. This is not a confirmed "
                "vulnerability. Verify the behavior within approved scope."
            ),
            evidence=json.dumps(finding_evidence, ensure_ascii=False),
            remediation=(
                "Review the observation, reproduce only in an authorized "
                "controlled environment, and document the verified cause "
                "before assigning final severity."
            ),
        )
        db.add(potential_finding)
        db.flush()

    return {
        "test_case": test_case,
        "record": record,
        "observation": observation,
        "potential_finding": potential_finding,
        "manual_review_required": True,
        "network_requests_made": 0,
        "payloads_executed": 0,
    }
