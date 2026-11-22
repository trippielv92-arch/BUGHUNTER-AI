"""Evidence aggregation for researcher-owned role comparisons.

This module compares only response metadata already collected by the bounded
assessment engine. It never sends requests, stores response values, or confirms
an authorization vulnerability.
"""

from collections import defaultdict


def summarize_role_authorization_observations(observations):
    """Group endpoint observations by role and identify behavioral deltas."""
    grouped = defaultdict(dict)

    for item in observations or []:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint") or "").strip()
        role = str(item.get("role_label") or "").strip()
        if not endpoint or not role:
            continue

        try:
            status = int(item.get("status"))
        except (TypeError, ValueError):
            continue

        fields = item.get("sensitive_field_names") or []
        if not isinstance(fields, (list, tuple, set)):
            fields = []

        # Keep names only; response values and credentials are never accepted.
        grouped[endpoint][role[:80]] = {
            "status": status,
            "sensitive_field_names": sorted({
                str(name)[:120] for name in fields
                if isinstance(name, str) and name.strip()
            }),
            "response_truncated": bool(item.get("response_truncated")),
        }

    summaries = []
    for endpoint, roles in sorted(grouped.items()):
        if len(roles) < 2:
            continue

        signatures = {
            (value["status"], tuple(value["sensitive_field_names"]))
            for value in roles.values()
        }
        difference = len(signatures) > 1
        summaries.append({
            "endpoint": endpoint,
            "roles_compared": sorted(roles),
            "role_count": len(roles),
            "role_observations": roles,
            "behavioral_difference_observed": difference,
            "interpretation": (
                "Different response status or recognized sensitive field "
                "names were observed across researcher-owned role profiles. "
                "This is a review lead, not proof of broken access control."
                if difference else
                "No difference in response status or recognized sensitive "
                "field names was observed across the compared role profiles. "
                "This does not prove equivalent authorization."
            ),
            "response_values_recorded": False,
            "credential_values_recorded": False,
            "automatically_confirmed": False,
            "manual_review_required": True,
        })

    return summaries
