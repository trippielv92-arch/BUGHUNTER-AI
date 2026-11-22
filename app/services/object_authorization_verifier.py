"""Pure helpers for bounded verification of registered test resources."""
import hashlib
from urllib.parse import quote, urlsplit


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
):
    """Classify metadata only; a 2xx cross-account response remains a potential lead."""
    owner_status = int(owner_status)
    requester_status = int(requester_status)
    owner_digest = None
    requester_digest = None
    if not owner_truncated:
        owner_digest = hashlib.sha256(bytes(owner_body or b"")).hexdigest()
    if not requester_truncated:
        requester_digest = hashlib.sha256(bytes(requester_body or b"")).hexdigest()
    same_representation = (
        owner_digest is not None
        and requester_digest is not None
        and owner_digest == requester_digest
    )

    if not 200 <= owner_status < 300:
        outcome = "owner_access_not_verified"
    elif 200 <= requester_status < 300:
        outcome = "potential_cross_account_access"
    elif requester_status in {401, 403}:
        outcome = "cross_account_access_denied"
    else:
        outcome = "inconclusive"

    return {
        "outcome": outcome,
        "owner_status": owner_status,
        "requester_status": requester_status,
        "same_response_representation": same_representation,
        "owner_response_truncated": bool(owner_truncated),
        "requester_response_truncated": bool(requester_truncated),
        "response_values_recorded": False,
        "resource_identifier_recorded": False,
        "vulnerability_confirmed": False,
        "manual_review_required": True,
    }
