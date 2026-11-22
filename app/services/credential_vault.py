"""Encrypted, project-scoped credentials for researcher-owned test accounts.

Secrets are encrypted at rest with a deployment-managed Fernet key. The key
must be supplied through BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY and must never be
stored in the project database or source repository.
"""
import os

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from app.models.entities import ScopeAsset, TestCredentialProfile
from app.services.projects import require_active_project
from app.services.workflows import _normalize_scope_host


def _cipher():
    key = os.environ.get("BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY is required before "
            "test-account credentials can be stored or used."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key."
        ) from exc


def encrypt_secret(secret):
    value = str(secret or "")
    if not value or len(value) > 8192:
        raise ValueError("Credential secret must contain 1 to 8192 characters.")
    if "\\r" in value or "\\n" in value:
        raise ValueError("Credential secrets cannot contain line breaks.")
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted_secret):
    try:
        return _cipher().decrypt(
            str(encrypted_secret).encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(
            "A stored test credential could not be decrypted. "
            "Check that the original encryption key is configured."
        ) from exc


def create_test_credential_profile(
    db, project_id, host, name, role_label, auth_type, secret
):
    """Store one encrypted bearer token or Cookie header for an approved host."""
    project = require_active_project(db, project_id)
    if not project.scope_approved:
        raise ValueError("Approve the exact project scope before adding test accounts.")

    normalized_host = _normalize_scope_host(host)
    approved_hosts = {
        _normalize_scope_host(asset.host)
        for asset in db.scalars(
            select(ScopeAsset).where(
                ScopeAsset.project_id == project_id,
                ScopeAsset.included.is_(True),
                ScopeAsset.approved.is_(True),
            )
        ).all()
    }
    if normalized_host not in approved_hosts:
        raise ValueError(
            "Credential profiles must be attached to an exact approved in-scope host."
        )

    name = str(name or "").strip()
    role_label = str(role_label or "").strip()
    auth_type = str(auth_type or "").strip().lower()

    if not name or len(name) > 120:
        raise ValueError("Profile name must contain 1 to 120 characters.")
    if not role_label or len(role_label) > 80:
        raise ValueError("Role label must contain 1 to 80 characters.")
    if auth_type not in {"bearer", "cookie"}:
        raise ValueError("Supported credential types are bearer and cookie.")

    encrypted = encrypt_secret(secret)
    duplicate = db.scalar(
        select(TestCredentialProfile).where(
            TestCredentialProfile.project_id == project_id,
            TestCredentialProfile.host == normalized_host,
            TestCredentialProfile.name == name,
        ).limit(1)
    )
    if duplicate:
        raise ValueError("A credential profile with this name already exists for the host.")

    profile = TestCredentialProfile(
        project_id=project_id,
        host=normalized_host,
        name=name,
        role_label=role_label,
        auth_type=auth_type,
        encrypted_secret=encrypted,
        enabled=True,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def list_test_credential_profiles(db, project_id, host=None):
    """Return profile metadata only; encrypted material is never serialized."""
    statement = (
        select(TestCredentialProfile)
        .where(TestCredentialProfile.project_id == project_id)
        .order_by(TestCredentialProfile.id.asc())
    )
    if host:
        statement = statement.where(
            TestCredentialProfile.host == _normalize_scope_host(host)
        )
    return db.scalars(statement).all()


def load_test_credential_profiles(db, project_id, host):
    """Decrypt only enabled profiles bound to the exact current hunt host."""
    normalized_host = _normalize_scope_host(host)
    profiles = db.scalars(
        select(TestCredentialProfile).where(
            TestCredentialProfile.project_id == project_id,
            TestCredentialProfile.host == normalized_host,
            TestCredentialProfile.enabled.is_(True),
        ).order_by(TestCredentialProfile.id.asc())
    ).all()

    return [
        {
            "id": profile.id,
            "name": profile.name,
            "role_label": profile.role_label,
            "auth_type": profile.auth_type,
            "secret": decrypt_secret(profile.encrypted_secret),
        }
        for profile in profiles
    ]


def delete_test_credential_profile(db, project_id, profile_id):
    profile = db.scalar(
        select(TestCredentialProfile).where(
            TestCredentialProfile.id == profile_id,
            TestCredentialProfile.project_id == project_id,
        )
    )
    if profile is None:
        raise ValueError("Test credential profile not found.")
    db.delete(profile)
    db.commit()
    return True
