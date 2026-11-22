import pytest
from cryptography.fernet import Fernet

from app.services.credential_vault import (
    create_test_credential_profile,
    decrypt_secret,
    delete_test_credential_profile,
    encrypt_secret,
    load_test_credential_profiles,
)
from app.services.projects import (
    add_scope_asset,
    approve_scope,
    create_project,
)


def _approved_project(db):
    project = create_project(
        db, "Credential vault test", "https://example.com"
    )
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def test_credential_secret_is_encrypted_and_round_trips(monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    secret = "researcher-owned-short-lived-token"
    encrypted = encrypt_secret(secret)

    assert secret not in encrypted
    assert encrypted != secret
    assert decrypt_secret(encrypted) == secret


def test_credential_encryption_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="is required"):
        encrypt_secret("not-stored")


def test_credential_headers_reject_line_breaks(monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    with pytest.raises(ValueError, match="line breaks"):
        encrypt_secret("token-value" + chr(13) + chr(10) + "Authorization: injected")


def test_profiles_are_bound_to_exact_approved_hosts(db, monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = _approved_project(db)

    with pytest.raises(ValueError, match="exact approved"):
        create_test_credential_profile(
            db, project.id, "other.example.com",
            "other", "standard", "bearer", "token-value",
        )


def test_profiles_store_ciphertext_and_decrypt_only_for_bound_host(
    db, monkeypatch
):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = _approved_project(db)
    secret = "owner-test-account-token"

    profile = create_test_credential_profile(
        db, project.id, "example.com",
        "owner", "owner", "bearer", secret,
    )
    assert profile.encrypted_secret != secret
    assert secret not in profile.encrypted_secret

    loaded = load_test_credential_profiles(
        db, project.id, "example.com"
    )
    assert len(loaded) == 1
    assert loaded[0]["secret"] == secret
    assert loaded[0]["role_label"] == "owner"

    assert load_test_credential_profiles(
        db, project.id, "sub.example.com"
    ) == []


def test_credential_profile_can_be_deleted(db, monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = _approved_project(db)
    profile = create_test_credential_profile(
        db, project.id, "example.com",
        "standard", "standard", "cookie", "session=owned-test-session",
    )

    assert delete_test_credential_profile(
        db, project.id, profile.id
    ) is True
    assert load_test_credential_profiles(
        db, project.id, "example.com"
    ) == []
