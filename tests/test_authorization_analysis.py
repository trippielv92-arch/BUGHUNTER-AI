from app.services.authorization_analysis import (
    summarize_role_authorization_observations,
)


def test_role_comparison_requires_two_distinct_roles():
    result = summarize_role_authorization_observations([
        {
            "endpoint": "https://example.test/api/profile",
            "role_label": "owner",
            "status": 200,
            "sensitive_field_names": ["email"],
        },
    ])
    assert result == []


def test_role_comparison_detects_metadata_difference_without_values():
    result = summarize_role_authorization_observations([
        {
            "endpoint": "https://example.test/api/profile",
            "role_label": "owner",
            "status": 200,
            "sensitive_field_names": ["email", "phone"],
        },
        {
            "endpoint": "https://example.test/api/profile",
            "role_label": "standard",
            "status": 403,
            "sensitive_field_names": [],
        },
    ])
    assert len(result) == 1
    summary = result[0]
    assert summary["behavioral_difference_observed"] is True
    assert summary["roles_compared"] == ["owner", "standard"]
    assert summary["automatically_confirmed"] is False
    assert summary["response_values_recorded"] is False
    assert "private@example.test" not in str(summary)


def test_role_comparison_reports_no_observed_difference_conservatively():
    result = summarize_role_authorization_observations([
        {
            "endpoint": "https://example.test/api/profile",
            "role_label": "owner",
            "status": 200,
            "sensitive_field_names": ["email"],
        },
        {
            "endpoint": "https://example.test/api/profile",
            "role_label": "standard",
            "status": 200,
            "sensitive_field_names": ["email"],
        },
    ])
    assert result[0]["behavioral_difference_observed"] is False
    assert result[0]["manual_review_required"] is True


def test_role_comparison_ignores_invalid_and_unlabelled_observations():
    result = summarize_role_authorization_observations([
        None,
        {"endpoint": "", "role_label": "owner", "status": 200},
        {"endpoint": "https://example.test", "role_label": "guest",
         "status": "invalid"},
    ])
    assert result == []
