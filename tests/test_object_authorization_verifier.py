import pytest

from app.services.object_authorization_verifier import (
    build_registered_resource_url,
    compare_owned_resource_access,
    select_distinct_requester_profiles,
)


def test_builds_exact_encoded_resource_url():
    result = build_registered_resource_url(
        "https://example.com/api/orders/{id}",
        "synthetic/order ?#1",
        "example.com",
    )
    assert result == "https://example.com/api/orders/synthetic%2Forder%20%3F%231"


@pytest.mark.parametrize("template", [
    "http://example.com/api/orders/{id}",
    "https://other.example.com/api/orders/{id}",
    "https://example.com/api/orders/{id}?expand=true",
    "https://example.com/api/orders/{id}#fragment",
    "https://example.com/api/orders/{id}/items/{id}",
])
def test_rejects_out_of_boundary_resource_urls(template):
    with pytest.raises(ValueError, match="approved verification boundary"):
        build_registered_resource_url(template, "owned-123", "example.com")


def test_requester_profiles_must_have_distinct_credential_material():
    owner = {"id": 1, "secret": "owner-token"}
    profiles = [
        {"id": 2, "secret": "owner-token"},
        {"id": 3, "secret": "viewer-token"},
        {"id": 4, "secret": "support-token"},
    ]
    result = select_distinct_requester_profiles(owner, profiles, limit=2)
    assert [item["id"] for item in result] == [3, 4]


def test_successful_cross_account_get_is_only_a_potential_lead():
    result = compare_owned_resource_access(
        200, 200, b'{"id":"same"}', b'{"id":"same"}'
    )
    assert result["outcome"] == "potential_cross_account_access"
    assert result["same_response_representation"] is True
    assert result["vulnerability_confirmed"] is False
    assert result["response_values_recorded"] is False


def test_different_response_body_is_still_not_reported_as_confirmed():
    result = compare_owned_resource_access(
        200, 200, b'{"id":"owner"}', b'{"id":"other"}'
    )
    assert result["outcome"] == "potential_cross_account_access"
    assert result["same_response_representation"] is False
    assert result["vulnerability_confirmed"] is False


def test_denied_and_inconclusive_responses_are_distinguished():
    denied = compare_owned_resource_access(200, 403, b"owner", b"")
    unknown = compare_owned_resource_access(200, 500, b"owner", b"error")
    assert denied["outcome"] == "cross_account_access_denied"
    assert unknown["outcome"] == "inconclusive"


def test_owner_must_first_access_the_registered_resource():
    result = compare_owned_resource_access(403, 200, b"", b"body")
    assert result["outcome"] == "owner_access_not_verified"
    assert result["vulnerability_confirmed"] is False


def test_truncated_responses_are_never_claimed_identical():
    result = compare_owned_resource_access(
        200, 200, b"same", b"same",
        owner_truncated=True,
    )
    assert result["same_response_representation"] is False
