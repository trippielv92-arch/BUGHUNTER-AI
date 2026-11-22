"""Encrypted registry of researcher-owned API resources.

A mapping is an explicit researcher attestation, not an automated ownership
proof. Resource references are encrypted at rest and never returned by APIs.
No requests are made by this module.
"""
import hashlib
import hmac
import re
from urllib.parse import urlsplit

from sqlalchemy import select

from app.models.entities import (
    ResearcherOwnedResource,
    ScopeAsset,
    TestCredentialProfile,
)
from app.services.credential_vault import encrypt_secret
from app.services.projects import require_active_project
from app.services.workflows import _normalize_scope_host


def derive_project_fingerprint_key(project_id):
    """Derive a stable keyed fingerprint key isolated to one project."""
    import os

    key = os.environ.get("BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY is required for owned-resource mappings."
        )
    try:
        key_bytes = key.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RuntimeError(
            "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY must be valid ASCII."
        ) from exc
    return hmac.new(
        key_bytes,
        f"bughunter-project:{int(project_id)}".encode("ascii"),
        hashlib.sha256,
    ).digest()


def fingerprint_resource_reference(reference, project_id):
    return hmac.new(
        derive_project_fingerprint_key(project_id),
        str(reference).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _validate_template(endpoint_template, normalized_host):
    value = str(endpoint_template or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("Endpoint template must contain 1 to 2048 characters.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Endpoint template is not a valid URL.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or _normalize_scope_host(parsed.hostname) != normalized_host
        or parsed.path.count("{id}") != 1
        or parsed.path.count("{") != 1
        or parsed.path.count("}") != 1
    ):
        raise ValueError(
            "Endpoint template must be HTTPS on the exact approved host, "
            "without query or fragment, and contain exactly one {id} path placeholder."
        )
    return value


def register_researcher_owned_resource(
    db,
    project_id,
    host,
    endpoint_template,
    owner_profile_id,
    resource_reference,
    attestation_note,
):
    project = require_active_project(db, project_id)
    if not project.scope_approved:
        raise ValueError("Approve the exact project scope before registering resources.")

    normalized_host = _normalize_scope_host(host)
    approved = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project_id,
            ScopeAsset.included.is_(True),
            ScopeAsset.approved.is_(True),
        )
    ).all()
    approved_hosts = set()
    for asset in approved:
        try:
            approved_hosts.add(_normalize_scope_host(asset.host))
        except ValueError:
            continue
    if normalized_host not in approved_hosts:
        raise ValueError("Owned resources must use an exact approved in-scope host.")

    template = _validate_template(endpoint_template, normalized_host)
    profile = db.scalar(
        select(TestCredentialProfile).where(
            TestCredentialProfile.id == owner_profile_id,
            TestCredentialProfile.project_id == project_id,
            TestCredentialProfile.host == normalized_host,
            TestCredentialProfile.enabled.is_(True),
        )
    )
    if profile is None:
        raise ValueError(
            "Owner profile must be enabled and bound to the same approved host and project."
        )

    reference = str(resource_reference or "")
    if (
        not reference
        or reference != reference.strip()
        or len(reference) > 512
        or any(ord(char) < 32 or ord(char) == 127 for char in reference)
    ):
        raise ValueError("Resource reference must be 1 to 512 printable characters.")

    if reference in template:
        raise ValueError("Endpoint template must not contain the raw resource identifier.")

    note = str(attestation_note or "").strip()
    if len(note) < 20 or len(note) > 2000:
        raise ValueError("Ownership attestation note must contain 20 to 2000 characters.")
    if re.search(
        rf"(?<![A-Za-z0-9]){re.escape(reference)}(?![A-Za-z0-9])",
        note,
    ):
        raise ValueError("Ownership attestation note must not contain the raw resource identifier.")
    if re.search(
        r"(?i)\b(?:authorization\s*[:=]|cookie\s*[:=]|"
        r"session\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=]|"
        r"password\s*[:=]|secret\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]{12,})",
        note,
    ):
        raise ValueError("Ownership attestation note must not contain credentials or secret values.")

    fingerprint = fingerprint_resource_reference(reference, project_id)
    duplicate = db.scalar(
        select(ResearcherOwnedResource).where(
            ResearcherOwnedResource.project_id == project_id,
            ResearcherOwnedResource.host == normalized_host,
            ResearcherOwnedResource.resource_fingerprint == fingerprint,
        ).limit(1)
    )
    if duplicate:
        raise ValueError("This resource is already registered for the project.")

    resource = ResearcherOwnedResource(
        project_id=project_id,
        host=normalized_host,
        endpoint_template=template,
        owner_profile_id=profile.id,
        resource_fingerprint=fingerprint,
        encrypted_reference=encrypt_secret(reference),
        attestation_note=note,
        ownership_attested=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource


def decrypt_registered_reference(resource):
    """Internal worker-only decryption helper; never expose through API output."""
    from app.services.credential_vault import decrypt_secret

    if not resource.ownership_attested:
        raise ValueError("Resource ownership has not been attested.")
    return decrypt_secret(resource.encrypted_reference)
