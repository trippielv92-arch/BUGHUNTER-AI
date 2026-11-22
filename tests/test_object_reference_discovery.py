import json

from app.services.object_reference_discovery import (
    discover_object_references,
    summarize_object_reference_observations,
    correlate_registered_resource_summaries,
)


SALT = b"test-only-salt-material-at-least-16"


def test_discovers_id_fields_without_returning_raw_values():
    body = json.dumps({
        "user": {"id": "researcher-owned-123", "email": "private@example.test"},
        "records": [{"record_id": 42, "name": "Synthetic record"}],
    }).encode()
    result = discover_object_references("application/json", body, SALT)
    assert {item["field_name"] for item in result} == {"id", "record_id"}
    assert "researcher-owned-123" not in str(result)
    assert "42" not in str(result)
    assert all(len(item["fingerprint"]) == 64 for item in result)


def test_excludes_secrets_personal_fields_and_boolean_ids():
    body = (
        b'{"id":true,"session_id":"dont-track","access_token":"secret",'
        b'"email":"private@example.test","customer_id":"cust-123"}'
    )
    result = discover_object_references("application/json", body, SALT)
    assert [item["field_name"] for item in result] == ["customer_id"]
    assert "cust-123" not in str(result)


def test_uses_per_hunt_salt_for_fingerprints():
    body = b'{"id":"same-reference"}'
    first = discover_object_references("application/json", body, SALT)
    second = discover_object_references(
        "application/json", body, b"different-salt-material-123456"
    )
    assert first[0]["fingerprint"] != second[0]["fingerprint"]


def test_rejects_non_json_invalid_and_oversized_responses():
    assert discover_object_references("text/html", b'{"id":1}', SALT) == []
    assert discover_object_references("application/json", b"{", SALT) == []
    assert discover_object_references(
        "application/json", b"x" * 500_001, SALT
    ) == []


def test_correlates_same_reference_across_test_account_roles():
    candidate = discover_object_references(
        "application/json", b'{"record_id":"owned-record"}', SALT
    )[0]
    result = summarize_object_reference_observations([
        {"endpoint": "https://app.example.test/api/profile",
         "role_label": "owner", "candidate": candidate},
        {"endpoint": "https://app.example.test/api/profile",
         "role_label": "viewer", "candidate": candidate},
    ])
    assert len(result) == 1
    assert result[0]["observed_across_multiple_roles"] is True
    assert result[0]["registry_fingerprint"] is None
    assert result[0]["roles_observing_reference"] == ["owner", "viewer"]
    assert result[0]["ownership_verified"] is False
    assert result[0]["network_requests_to_candidate_references"] == 0


def test_different_role_references_are_not_claimed_as_shared():
    owner = discover_object_references(
        "application/json", b'{"id":"owner-record"}', SALT
    )[0]
    viewer = discover_object_references(
        "application/json", b'{"id":"viewer-record"}', SALT
    )[0]
    result = summarize_object_reference_observations([
        {"endpoint": "https://app.example.test/api/profile",
         "role_label": "owner", "candidate": owner},
        {"endpoint": "https://app.example.test/api/profile",
         "role_label": "viewer", "candidate": viewer},
    ])
    assert len(result) == 2
    assert all(not item["observed_across_multiple_roles"] for item in result)


def test_summary_ignores_malformed_observations():
    assert summarize_object_reference_observations([
        None, {}, {"endpoint": "https://app.example.test", "candidate": {}}
    ]) == []

def test_registry_fingerprint_matches_registry_service(monkeypatch):
    from cryptography.fernet import Fernet
    from app.services.owned_resource_registry import (
        derive_project_fingerprint_key,
        fingerprint_resource_reference,
    )

    monkeypatch.setenv(
        "BUGHUNTER_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    reference = "synthetic-owned-record"
    key = derive_project_fingerprint_key(7)
    result = discover_object_references(
        "application/json",
        b'{"record_id":"synthetic-owned-record"}',
        SALT,
        fingerprint_key=key,
    )
    assert result[0]["registry_fingerprint"] == fingerprint_resource_reference(
        reference, 7
    )
    assert result[0]["registry_fingerprint"] != result[0]["fingerprint"]


def test_correlates_discovered_reference_to_attested_registry_without_verifying_ownership():
    candidate = discover_object_references(
        "application/json", b'{"id":"synthetic-owned-record"}',
        SALT, fingerprint_key=b"project-scoped-test-key-material",
    )[0]
    summary = summarize_object_reference_observations([
        {"endpoint": "https://example.test/api/orders", "role_label": "owner",
         "candidate": candidate}
    ])
    matched = correlate_registered_resource_summaries(
        summary,
        [{"id": 77, "resource_fingerprint": candidate["registry_fingerprint"]}],
    )
    assert matched[0]["registered_resource_match"] is True
    assert matched[0]["registered_owned_resource_id"] == 77
    assert matched[0]["ownership_attested"] is True
    assert matched[0]["ownership_verified"] is False
    assert matched[0]["manual_ownership_mapping_required"] is False


def test_unmatched_discovered_reference_stays_unmapped():
    candidate = discover_object_references(
        "application/json", b'{"id":"unmapped-record"}',
        SALT, fingerprint_key=b"project-scoped-test-key-material",
    )[0]
    summary = summarize_object_reference_observations([
        {"endpoint": "https://example.test/api/orders", "role_label": "owner",
         "candidate": candidate}
    ])
    result = correlate_registered_resource_summaries(summary, [])
    assert result[0]["registered_resource_match"] is False
    assert result[0]["registered_owned_resource_id"] is None
    assert result[0]["ownership_verified"] is False

