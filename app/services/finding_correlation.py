"""Conservative finding correlation and duplicate review.

Read-only analysis. No finding is deleted, merged, closed or confirmed.
"""

import hashlib
import re
from collections import defaultdict
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

from app.models.entities import Finding


def _normal_text(value):
    value = str(value or "").lower().strip()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def _normal_asset(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    try:
        parsed = urlsplit(raw)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            port = parsed.port
            if port and not (
                (parsed.scheme.lower() == "https" and port == 443)
                or (parsed.scheme.lower() == "http" and port == 80)
            ):
                host = f"{host}:{port}"

            path = re.sub(r"/+", "/", parsed.path or "/")
            path = path.rstrip("/") or "/"
            return urlunsplit((
                parsed.scheme.lower(),
                host,
                path,
                "",
                "",
            ))
    except (ValueError, TypeError):
        pass

    return _normal_text(raw)


def _fingerprint(finding):
    asset = _normal_asset(getattr(finding, "asset", ""))
    category = _normal_text(getattr(finding, "category", ""))
    title = _normal_text(getattr(finding, "title", ""))

    raw = "|".join((asset, category, title))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finding_summary(finding):
    return {
        "id": getattr(finding, "id", None),
        "title": str(getattr(finding, "title", "") or ""),
        "category": str(getattr(finding, "category", "") or ""),
        "asset": str(getattr(finding, "asset", "") or ""),
        "normalized_asset": _normal_asset(
            getattr(finding, "asset", "")
        ),
        "severity": str(getattr(finding, "severity", "") or ""),
        "confidence": str(getattr(finding, "confidence", "") or ""),
        "status": str(getattr(finding, "status", "") or ""),
        "fingerprint": _fingerprint(finding),
    }


def correlate_findings(findings, similarity_threshold=0.92):
    """Return exact duplicate groups and possible duplicate pairs."""
    findings = list(findings or [])
    summaries = [_finding_summary(item) for item in findings]

    exact_groups = defaultdict(list)
    for item in summaries:
        exact_groups[item["fingerprint"]].append(item)

    exact = [
        {
            "fingerprint": fingerprint,
            "match_type": "exact",
            "reason": (
                "Same normalized endpoint, category and normalized title."
            ),
            "findings": group,
            "finding_ids": [item["id"] for item in group],
        }
        for fingerprint, group in exact_groups.items()
        if len(group) > 1
    ]

    # Near-duplicate suggestions only compare records on the same
    # normalized asset and category. No fuzzy cross-endpoint matching.
    possible = []
    seen = set()

    for index, first in enumerate(summaries):
        for second in summaries[index + 1:]:
            if first["fingerprint"] == second["fingerprint"]:
                continue

            if not first["normalized_asset"]:
                continue

            if first["normalized_asset"] != second["normalized_asset"]:
                continue

            if _normal_text(first["category"]) != _normal_text(
                second["category"]
            ):
                continue

            pair = tuple(sorted((str(first["id"]), str(second["id"]))))
            if pair in seen:
                continue

            similarity = SequenceMatcher(
                None,
                _normal_text(first["title"]),
                _normal_text(second["title"]),
            ).ratio()

            if similarity >= similarity_threshold:
                seen.add(pair)
                possible.append({
                    "match_type": "possible",
                    "reason": (
                        "Same normalized endpoint and category; "
                        "finding titles are similar."
                    ),
                    "similarity": round(similarity, 3),
                    "findings": [first, second],
                    "finding_ids": [first["id"], second["id"]],
                })

    return {
        "exact_duplicates": exact,
        "possible_duplicates": possible,
        "findings_reviewed": len(summaries),
        "exact_group_count": len(exact),
        "possible_pair_count": len(possible),
        "automatic_merges": 0,
        "automatic_deletions": 0,
        "records_changed": 0,
        "manual_review_required": True,
    }


def analyze_project_finding_duplicates(db, project_id):
    """Read-only duplicate analysis for one project."""
    findings = (
        db.query(Finding)
        .filter(Finding.project_id == project_id)
        .order_by(Finding.id.asc())
        .all()
    )
    result = correlate_findings(findings)
    result["project_id"] = project_id
    return result
