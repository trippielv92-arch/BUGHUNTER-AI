"""Pure helpers for bounded verification of registered test resources."""
import hashlib
import json
import re
from urllib.parse import quote, urlsplit


_SOFT_DENIAL_PATTERNS = (
    re.compile(r"\b(?:access denied|not authorized|unauthorized|forbidden)\b", re.I),
    re.compile(r"\b(?:resource|record|object|item)\s+(?:was\s+)?not found\b", re.I),
    re.compile(r"\b(?:does not exist|no such (?:resource|record|object|item))\b", re.I),
    re.compile(r"\bplease sign in\b|\blog in to continue\b|\bauthentication required\b", re.I),
)


def _response_bytes(body):
    return body if isinstance(body, bytes) else str(body or "").encode("utf-8")


def response_is_usable_resource_representation(body, content_type="", truncated=False):
    """Reject empty, truncated, and recognizable soft-denial response bodies."""
    raw = _response_bytes(body)
    if truncated or not raw.strip():
        return False

    sample = raw[:65536].decode("utf-8", errors="replace")
    if any(pattern.search(sample) for pattern in _SOFT_DENIAL_PATTERNS):
        return False

    media_type = str(content_type or "").split(";", 1)[0].strip().lower()
    if "json" in media_type:
        try:
            payload = json.loads(sample)
        except (ValueError, TypeError):
            return True
        if isinstance(payload, dict):
            normalized_keys = {
                re.sub(r"[^a-z0-9]", "", str(key).lower())
                for key in payload
            }
            if normalized_keys.intersection({"error", "errors"}):
                # Error envelopes are not evidence that the resource itself
                # was returned, even when the endpoint responds with HTTP 200.
                return False
    if "html" in media_type or "<html" in sample[:1000].lower():
        if re.search(r"<input\b[^>]*type\s*=\s*['\"]?password", sample, re.I):
            return False
    return True


def build_registered_resource_url(endpoint_template, resource_reference, approved_host):
    """Substitute only the encrypted, researcher-registered ID into one path slot."""
    template = str(endpoint_template or "")
    reference = str(resource_reference or "")
    try:
        parsed = urlsplit(template)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid registered resource endpoint.") from exc

    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.hostname.lower().rstrip(".") != str(approved_host).lower().rstrip(".")
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.count("{id}") != 1
        or parsed.path.count("{") != 1
        or parsed.path.count("}") != 1
        or not reference
        or len(reference) > 512
    ):
        raise ValueError("Registered resource is outside the approved verification boundary.")

    return template.replace("{id}", quote(reference, safe=""))


def select_distinct_requester_profiles(owner_profile, profiles, limit=2):
    """Choose different credential material, not merely different profile labels."""
    if not isinstance(owner_profile, dict):
        return []
    owner_secret = str(owner_profile.get("secret") or "")
    if not owner_secret:
        return []
    owner_digest = hashlib.sha256(owner_secret.encode("utf-8")).digest()
    seen = {owner_digest}
    selected = []
    for profile in profiles or []:
        if not isinstance(profile, dict):
            continue
        if profile.get("id") == owner_profile.get("id"):
            continue
        secret = str(profile.get("secret") or "")
        if not secret:
            continue
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        if digest in seen:
            continue
        seen.add(digest)
        selected.append(profile)
        if len(selected) >= max(0, int(limit)):
            break
    return selected


def compare_owned_resource_access(
    owner_status,
    requester_status,
    owner_body,
    requester_body,
    owner_truncated=False,
    requester_truncated=False,
    owner_content_type="",
    requester_content_type="",
):
    """Classify bounded response metadata; never treat HTTP 2xx alone as proof."""
    owner_status = int(owner_status)
    requester_status = int(requester_status)
    owner_raw = _response_bytes(owner_body)
    requester_raw = _response_bytes(requester_body)
    owner_digest = None
    requester_digest = None
    if not owner_truncated:
        owner_digest = hashlib.sha256(owner_raw).hexdigest()
    if not requester_truncated:
        requester_digest = hashlib.sha256(requester_raw).hexdigest()
    same_representation = (
        owner_digest is not None
        and requester_digest is not None
        and owner_digest == requester_digest
    )
    owner_usable = response_is_usable_resource_representation(
        owner_raw, owner_content_type, owner_truncated
    )
    requester_usable = response_is_usable_resource_representation(
        requester_raw, requester_content_type, requester_truncated
    )
    owner_media = str(owner_content_type or "").split(";", 1)[0].strip().lower()
    requester_media = str(requester_content_type or "").split(";", 1)[0].strip().lower()
    media_type_compatible = not owner_media or not requester_media or owner_media == requester_media

    if not 200 <= owner_status < 300:
        outcome = "owner_access_not_verified"
    elif not owner_usable:
        outcome = "owner_response_not_resource_evidence"
    elif 200 <= requester_status < 300:
        outcome = (
            "potential_cross_account_access"
            if requester_usable and media_type_compatible
            else "inconclusive"
        )
    elif requester_status in {401, 403}:
        outcome = "cross_account_access_denied"
    else:
        outcome = "inconclusive"

    return {
        "outcome": outcome,
        "owner_status": owner_status,
        "requester_status": requester_status,
        "same_response_representation": same_representation,
        "owner_response_bytes": len(owner_raw),
        "requester_response_bytes": len(requester_raw),
        "owner_content_type": owner_media[:100],
        "requester_content_type": requester_media[:100],
        "response_media_types_compatible": media_type_compatible,
        "owner_response_usable_resource_evidence": owner_usable,
        "requester_response_usable_resource_evidence": requester_usable,
        "owner_response_truncated": bool(owner_truncated),
        "requester_response_truncated": bool(requester_truncated),
        "response_values_recorded": False,
        "resource_identifier_recorded": False,
        "vulnerability_confirmed": False,
        "manual_review_required": True,
    }
