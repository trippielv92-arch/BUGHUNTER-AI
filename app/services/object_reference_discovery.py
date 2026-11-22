"""Bounded discovery of object-reference metadata in API JSON responses.

Only field names, JSON pointers, value types, and per-hunt salted fingerprints
are returned. Raw identifiers and response values are never persisted. This
module never makes network requests or replays discovered identifiers.
"""
import hashlib
import hmac
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


def discover_object_references(content_type, body, salt, fingerprint_key=None):
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
                        if isinstance(fingerprint_key, bytes) and len(fingerprint_key) >= 16:
                            record["registry_fingerprint"] = hmac.new(
                                fingerprint_key,
                                identifier.encode("utf-8"),
                                hashlib.sha256,
                            ).hexdigest()
                        found[(child_pointer, digest)] = record
                if isinstance(value, (dict, list)):
                    pending.append((value, child_pointer))
        elif isinstance(current, list):
            for value in current[:500]:
                if isinstance(value, (dict, list)):
                    pending.append((value, pointer + "/*"))
    return list(found.values())[:_MAX_CANDIDATES]


def correlate_registered_resource_summaries(summaries, registered_resources):
    """Attach only project-local registry matches; never claim ownership is verified."""
    registered = {
        str(item.get("resource_fingerprint")): item.get("id")
        for item in registered_resources or []
        if isinstance(item, dict)
        and re.fullmatch(r"[0-9a-f]{64}", str(item.get("resource_fingerprint") or ""))
        and item.get("id") is not None
    }
    results = []
    for summary in summaries or []:
        if not isinstance(summary, dict):
            continue
        matched_id = registered.get(str(summary.get("registry_fingerprint") or ""))
        item = dict(summary)
        item["registered_resource_match"] = matched_id is not None
        item["registered_owned_resource_id"] = matched_id
        item["ownership_attested"] = matched_id is not None
        item["ownership_verified"] = False
        item["manual_ownership_mapping_required"] = matched_id is None
        results.append(item)
    return results


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
            "registry_fingerprint": str(candidate.get("registry_fingerprint") or ""),
        })

    summaries = []
    for (endpoint, fingerprint), records in sorted(grouped.items()):
        roles = sorted({record["role_label"] for record in records})
        pointers = sorted({record["json_pointer"] for record in records})
        registry_fingerprints = sorted({
            str(record.get("registry_fingerprint"))
            for record in records
            if re.fullmatch(
                r"[0-9a-f]{64}",
                str(record.get("registry_fingerprint") or ""),
            )
        })
        summaries.append({
            "endpoint": endpoint,
            "resource_fingerprint": fingerprint,
            "registry_fingerprint": (
                registry_fingerprints[0]
                if len(registry_fingerprints) == 1 else None
            ),
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
