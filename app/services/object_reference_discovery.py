"""Bounded discovery of object-reference metadata in API JSON responses.

Only field names, JSON pointers, value types, and per-hunt salted fingerprints
are returned. Raw identifiers and response values are never persisted. This
module never makes network requests or replays discovered identifiers.
"""
import hashlib
import json
import re
from collections import defaultdict

_ID_FIELD = re.compile(r"^(?:id|[a-z0-9]+_id|uuid|guid)$", re.IGNORECASE)
_SENSITIVE_FIELD = re.compile(
    r"token|secret|password|credential|session|cookie|email|phone|"
    r"address|passport|national|ssn|authorization",
    re.IGNORECASE,
)
_MAX_BYTES = 500_000
_MAX_NODES = 5_000
_MAX_CANDIDATES = 200


def _pointer_part(value):
    return str(value).replace("~", "~0").replace("/", "~1")[:120]


def discover_object_references(content_type, body, salt):
    """Extract candidate ID-like fields without retaining their values."""
    if "json" not in str(content_type or "").lower():
        return []
    raw = body if isinstance(body, bytes) else str(body or "").encode("utf-8")
    if len(raw) > _MAX_BYTES or not isinstance(salt, bytes) or len(salt) < 16:
        return []
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return []

    found = {}
    pending = [(document, "")]
    visited = 0
    while pending and visited < _MAX_NODES and len(found) < _MAX_CANDIDATES:
        current, pointer = pending.pop()
        visited += 1
        if isinstance(current, dict):
            for key, value in list(current.items())[:500]:
                name = str(key)[:120]
                child_pointer = pointer + "/" + _pointer_part(name)
                normalized = name.lower()
                if (
                    _ID_FIELD.fullmatch(normalized)
                    and not _SENSITIVE_FIELD.search(normalized)
                    and isinstance(value, (str, int))
                    and not isinstance(value, bool)
                ):
                    identifier = str(value).strip()
                    if identifier and len(identifier) <= 512:
                        digest = hashlib.sha256(
                            salt + b":" + identifier.encode("utf-8")
                        ).hexdigest()
                        record = {
                            "json_pointer": child_pointer[:500],
                            "field_name": name,
                            "value_type": "integer" if isinstance(value, int) else "string",
                            "fingerprint": digest,
                        }
                        found[(child_pointer, digest)] = record
                if isinstance(value, (dict, list)):
                    pending.append((value, child_pointer))
        elif isinstance(current, list):
            for value in current[:500]:
                if isinstance(value, (dict, list)):
                    pending.append((value, pointer + "/*"))
    return list(found.values())[:_MAX_CANDIDATES]


def summarize_object_reference_observations(observations):
    """Correlate candidate fingerprints across observed account roles."""
    grouped = defaultdict(list)
    for item in observations or []:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint") or "")[:2048]
        role = str(item.get("role_label") or "")[:80]
        candidate = item.get("candidate")
        if not endpoint or not role or not isinstance(candidate, dict):
            continue
        fingerprint = str(candidate.get("fingerprint") or "")
        pointer = str(candidate.get("json_pointer") or "")[:500]
        field_name = str(candidate.get("field_name") or "")[:120]
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or not pointer:
            continue
        grouped[(endpoint, fingerprint)].append({
            "role_label": role,
            "json_pointer": pointer,
            "field_name": field_name,
            "value_type": str(candidate.get("value_type") or "")[:20],
        })

    summaries = []
    for (endpoint, fingerprint), records in sorted(grouped.items()):
        roles = sorted({record["role_label"] for record in records})
        pointers = sorted({record["json_pointer"] for record in records})
        summaries.append({
            "endpoint": endpoint,
            "resource_fingerprint": fingerprint,
            "roles_observing_reference": roles,
            "json_pointers": pointers[:20],
            "field_names": sorted({record["field_name"] for record in records})[:20],
            "observation_count": len(records),
            "observed_across_multiple_roles": len(roles) > 1,
            "ownership_verified": False,
            "access_control_conclusion": "none",
            "network_requests_to_candidate_references": 0,
            "raw_object_identifier_recorded": False,
            "response_values_recorded": False,
            "manual_ownership_mapping_required": True,
        })
    return summaries
