"""Conservative object-ownership authorization evidence analysis.

Evaluates researcher-supplied observations about records owned by
researcher-controlled test accounts. Performs no requests and never stores
raw object identifiers or response values. A policy mismatch is a manual
review lead, not a confirmed vulnerability.
"""
import hashlib
import re
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit

_VALID_ACCESS = {"allowed", "denied", "unknown"}


def _clean_label(value, limit=80):
    return str(value or "").strip()[:limit]


def _safe_endpoint(value, resource_reference):
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.netloc:
            return ""
        reference = str(resource_reference or "").strip()
        path = parsed.path
        if reference:
            path = path.replace(reference, "{resource}")
        segments = []
        for segment in path.split("/"):
            if (
                segment.isdigit()
                or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", segment)
                or re.fullmatch(r"[0-9a-fA-F]{24,}", segment)
            ):
                segment = "{id}"
            segments.append(segment)
        return urlunsplit((
            parsed.scheme.lower(), parsed.netloc.lower(),
            "/".join(segments), "", ""
        ))
    except (TypeError, ValueError):
        return ""


def _resource_fingerprint(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def analyze_object_ownership_observations(observations):
    """Summarize ownership/access observations without retaining object IDs.

    Each accepted observation must explicitly assert that the resource is
    researcher-controlled and its ownership was independently verified.
    expected_access expresses documented policy. observed_access is a
    reviewer-supplied outcome, never inferred from an HTTP status or body.
    """
    grouped = defaultdict(list)

    for item in observations or []:
        if not isinstance(item, dict):
            continue
        if item.get("researcher_controlled") is not True:
            continue
        if item.get("ownership_verified") is not True:
            continue

        resource_reference = item.get("resource_reference")
        endpoint = _safe_endpoint(item.get("endpoint"), resource_reference)
        owner = _clean_label(item.get("resource_owner_role"))
        requester = _clean_label(item.get("requester_role"))
        fingerprint = _resource_fingerprint(resource_reference)
        expected = item.get("expected_access")
        observed = str(item.get("observed_access") or "").strip().lower()

        if (
            not endpoint or not owner or not requester or not fingerprint
            or not isinstance(expected, bool)
            or observed not in _VALID_ACCESS
        ):
            continue

        try:
            status = int(item.get("status"))
        except (TypeError, ValueError):
            continue
        if not 100 <= status <= 599:
            continue

        mismatch = (
            observed != "unknown"
            and observed != ("allowed" if expected else "denied")
        )
        grouped[(endpoint, fingerprint)].append({
            "resource_owner_role": owner,
            "requester_role": requester,
            "expected_access": expected,
            "observed_access": observed,
            "status": status,
            "policy_mismatch_observed": mismatch,
        })

    summaries = []
    for (endpoint, fingerprint), records in sorted(grouped.items()):
        mismatch_records = [
            record for record in records
            if record["policy_mismatch_observed"]
        ]
        cross_owner_lead = any(
            record["policy_mismatch_observed"]
            and record["observed_access"] == "allowed"
            and record["expected_access"] is False
            and record["requester_role"] != record["resource_owner_role"]
            for record in records
        )
        summaries.append({
            "endpoint": endpoint,
            "resource_fingerprint_sha256": fingerprint,
            "observations": records,
            "observation_count": len(records),
            "policy_mismatch_observed": bool(mismatch_records),
            "cross_owner_access_lead": cross_owner_lead,
            "interpretation": (
                "A researcher-controlled record was reported accessible to "
                "a role that should not have access. Verify the access policy "
                "and reproduce only with controlled test accounts."
                if cross_owner_lead else (
                    "An observed access outcome differs from the supplied "
                    "policy expectation; manual review is required."
                    if mismatch_records else
                    "No access-policy mismatch was reported. Unknown "
                    "outcomes are inconclusive, not proof of authorization."
                )
            ),
            "raw_object_identifier_recorded": False,
            "response_values_recorded": False,
            "automatically_confirmed": False,
            "manual_review_required": True,
        })

    return summaries
