import pytest
from cryptography.fernet import Fernet

from app.models.entities import ResearcherOwnedResource
from app.services.owned_resource_registry import (
    decrypt_registered_reference,
    register_researcher_owned_resource,
)
from app.services.credential_vault import create_test_credential_profile
from app.services.projects import add_scope_asset, approve_scope, create_project


def _setup(db, monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = create_project(db, "Owned resource test", "https://example.com")
    project.policy_text = "Authorized testing of example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    profile = create_test_credential_profile(
        db, project.id, "example.com",
        "owner-account", "owner", "bearer", "owner-test-token",
    )
    return project, profile


def test_resource_reference_is_encrypted_and_not_returned(db, monkeypatch):
    project, profile = _setup(db, monkeypatch)
    reference = "synthetic-order-123"
    resource = register_researcher_owned_resource(
        db, project.id, "example.com",
        "https://example.com/api/orders/{id}", profile.id,
        reference, "I accessed this synthetic order with the owner account.",
    )
    assert resource.encrypted_reference != reference
    assert reference not in resource.encrypted_reference
    assert resource.resource_fingerprint
    assert decrypt_registered_reference(resource) == reference
    assert resource.ownership_attested is True


def test_resource_requires_enabled_owner_profile_for_same_host(db, monkeypatch):
    project, profile = _setup(db, monkeypatch)
    with pytest.raises(ValueError, match="Owner profile"):
        register_researcher_owned_resource(
            db, project.id, "example.com",
            "https://example.com/api/orders/{id}", profile.id + 100,
            "synthetic-order-123", "Owner account accessed this synthetic order.",
        )


@pytest.mark.parametrize("template", [
    "http://example.com/api/orders/{id}",
    "https://other.example.com/api/orders/{id}",
    "https://example.com/api/orders/{id}?include=all",
    "https://example.com/api/orders/{id}/items/{id}",
    "https://example.com/api/orders/123",
])
def test_rejects_unsafe_or_ambiguous_endpoint_templates(db, monkeypatch, template):
    project, profile = _setup(db, monkeypatch)
    with pytest.raises(ValueError, match="Endpoint template"):
        register_researcher_owned_resource(
            db, project.id, "example.com", template, profile.id,
            "synthetic-order-123", "Owner account accessed this synthetic order.",
        )


def test_resource_requires_explicit_ownership_attestation_note(db, monkeypatch):
    project, profile = _setup(db, monkeypatch)
    with pytest.raises(ValueError, match="attestation note"):
        register_researcher_owned_resource(
            db, project.id, "example.com",
            "https://example.com/api/orders/{id}", profile.id,
            "synthetic-order-123", "too short",
        )


def test_resource_requires_approved_scope(db, monkeypatch):
    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    project = create_project(db, "Draft project", "https://example.com")
    with pytest.raises(ValueError, match="Approve the exact"):
        register_researcher_owned_resource(
            db, project.id, "example.com",
            "https://example.com/api/orders/{id}", 1,
            "synthetic-order-123", "Owner account accessed this synthetic order.",
        )


def test_duplicate_resource_registration_is_blocked(db, monkeypatch):
    project, profile = _setup(db, monkeypatch)
    args = (
        db, project.id, "example.com",
        "https://example.com/api/orders/{id}", profile.id,
        "synthetic-order-123", "Owner account accessed this synthetic order.",
    )
    register_researcher_owned_resource(*args)
    with pytest.raises(ValueError, match="already registered"):
        register_researcher_owned_resource(*args)


def test_unattested_resource_cannot_be_decrypted(db, monkeypatch):
    project, profile = _setup(db, monkeypatch)
    resource = register_researcher_owned_resource(
        db, project.id, "example.com",
        "https://example.com/api/orders/{id}", profile.id,
        "synthetic-order-123", "Owner account accessed this synthetic order.",
    )
    resource.ownership_attested = False
    with pytest.raises(ValueError, match="not been attested"):
        decrypt_registered_reference(resource)

def test_owner_profile_cannot_be_deleted_while_resource_mappings_exist(
    db, monkeypatch
):
    project, profile = _setup(db, monkeypatch)
    register_researcher_owned_resource(
        db, project.id, "example.com",
        "https://example.com/api/orders/{id}", profile.id,
        "synthetic-order-123", "Owner account accessed this synthetic order.",
    )
    from app.services.credential_vault import delete_test_credential_profile
    with pytest.raises(ValueError, match="resource mappings first"):
        delete_test_credential_profile(db, project.id, profile.id)
