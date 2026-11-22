import hashlib

from app.services.object_authorization_analysis import (
    analyze_object_ownership_observations,
)


def _observation(**overrides):
    value = {
        "endpoint": "https://app.example.test/api/records/{record_id}",
        "resource_reference": "researcher-test-record-123",
        "resource_owner_role": "owner",
        "requester_role": "standard",
        "researcher_controlled": True,
        "ownership_verified": True,
        "expected_access": False,
        "observed_access": "allowed",
        "status": 200,
    }
    value.update(overrides)
    return value


def test_cross_owner_access_mismatch_is_a_manual_review_lead():
    result = analyze_object_ownership_observations([_observation()])
    assert len(result) == 1
    summary = result[0]
    assert summary["policy_mismatch_observed"] is True
    assert summary["cross_owner_access_lead"] is True
    assert summary["automatically_confirmed"] is False
    assert summary["manual_review_required"] is True


def test_raw_object_identifier_is_hashed_and_not_returned():
    reference = "researcher-test-record-123"
    summary = analyze_object_ownership_observations([_observation()])[0]
    assert summary["resource_fingerprint_sha256"] == hashlib.sha256(
        reference.encode("utf-8")
    ).hexdigest()
    assert reference not in str(summary)
    assert summary["raw_object_identifier_recorded"] is False


def test_expected_owner_access_is_not_flagged():
    result = analyze_object_ownership_observations([
        _observation(
            requester_role="owner",
            expected_access=True,
            observed_access="allowed",
        )
    ])
    assert result[0]["policy_mismatch_observed"] is False
    assert result[0]["cross_owner_access_lead"] is False


def test_denied_cross_owner_access_matches_policy():
    result = analyze_object_ownership_observations([
        _observation(observed_access="denied", status=403)
    ])
    assert result[0]["policy_mismatch_observed"] is False
    assert result[0]["cross_owner_access_lead"] is False


def test_unknown_access_outcome_is_inconclusive():
    result = analyze_object_ownership_observations([
        _observation(observed_access="unknown", status=500)
    ])
    assert result[0]["policy_mismatch_observed"] is False
    assert result[0]["cross_owner_access_lead"] is False


def test_unverified_or_non_researcher_controlled_records_are_ignored():
    result = analyze_object_ownership_observations([
        _observation(ownership_verified=False),
        _observation(researcher_controlled=False),
    ])
    assert result == []


def test_invalid_or_incomplete_observations_are_ignored():
    result = analyze_object_ownership_observations([
        _observation(resource_reference=""),
        _observation(expected_access="false"),
        _observation(observed_access="maybe"),
        _observation(status=700),
    ])
    assert result == []



def test_endpoint_query_and_concrete_numeric_object_ids_are_redacted():
    summary = analyze_object_ownership_observations([
        _observation(
            endpoint="https://app.example.test/api/records/987654?token=secret"
        )
    ])[0]
    assert summary["endpoint"] == (
        "https://app.example.test/api/records/{id}"
    )
    assert "987654" not in str(summary)
    assert "token=secret" not in str(summary)
