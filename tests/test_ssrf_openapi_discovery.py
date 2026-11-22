import json

from sqlalchemy import select

from app.models.entities import Finding, ScanCheck
from app.services import engine
from app.services.projects import add_scope_asset, approve_scope, create_project
from app.services.validation import validate_project_findings


def _approved_project(db):
    project = create_project(db, "OpenAPI SSRF review", "https://example.com")
    project.policy_text = "Authorized test policy for example.com."
    add_scope_asset(db, project.id, "example.com")
    approve_scope(db, project)
    return project


def test_openapi_metadata_identifies_specific_url_input_names():
    document = {
        "components": {
            "schemas": {
                "ImportRequest": {
                    "type": "object",
                    "properties": {
                        "sourceUrl": {"type": "string"},
                        "displayName": {"type": "string"},
                    },
                }
            }
        }
    }
    path_item = {}
    operation = {
        "parameters": [
            {"name": "image_url", "in": "query"},
            {"name": "redirect_uri", "in": "query"},
        ],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/ImportRequest"}
                }
            }
        },
    }
    result = engine._openapi_operation_metadata(
        document, path_item, operation, "/api/import"
    )
    assert result["url_input_parameter_names"] == ["image_url"]
    assert result["url_input_body_field_names"] == ["sourceUrl"]
    assert "redirect_uri" not in result["url_input_parameter_names"]


def test_openapi_url_inputs_create_low_confidence_ssrf_review_lead(db):
    project = _approved_project(db)
    metadata = {
        "identity_parameter_names": [],
        "sensitive_parameter_names": [],
        "url_input_parameter_names": ["image_url"],
        "url_input_body_field_names": ["sourceUrl"],
        "request_body_field_names": ["sourceUrl"],
        "request_body_required": True,
        "security_declared": True,
        "security_explicitly_empty": False,
        "security_requirement_names": ["bearerAuth"],
        "available_security_scheme_names": ["bearerAuth"],
    }
    engine._record_openapi_operation_assessment(
        db, project.id, "https://example.com/api/import",
        "POST", "/api/import", "importRemoteImage", metadata,
    )

    finding = db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential server-side URL fetch input (SSRF review)",
    ))
    assert finding is not None
    assert finding.status == "potential"
    assert finding.severity == "low"
    assert finding.confidence == "low"
    assert "image_url" in finding.evidence
    assert "sourceUrl" in finding.evidence
    assert "network_requests_made" in finding.evidence


def test_ssrf_candidate_validation_supports_observation_without_confirmation(db):
    project = _approved_project(db)
    asset = "https://example.com/api/import"
    finding = Finding(
        project_id=project.id,
        title="Potential server-side URL fetch input (SSRF review)",
        category="SSRF Review",
        severity="low",
        confidence="low",
        status="potential",
        asset=asset,
        description="URL-like input fields were documented.",
        evidence='{"url_input_parameter_names":["image_url"]}',
        remediation="Review server-side URL handling.",
    )
    db.add(finding)
    db.add(ScanCheck(
        project_id=project.id,
        asset=asset,
        check_name="OpenAPI documented operation assessment",
        outcome="completed",
        details=json.dumps({
            "url_input_parameter_names": ["image_url"],
            "url_input_body_field_names": ["sourceUrl"],
            "network_requests_made": 0,
            "auto_confirmed": False,
        }),
    ))
    db.commit()

    counts = validate_project_findings(db, project.id)
    assert counts["supported_by_observation"] == 1
    record = db.scalar(select(ScanCheck).where(
        ScanCheck.project_id == project.id,
        ScanCheck.check_name == "Automated finding validation",
        ScanCheck.asset == asset,
    ))
    details = json.loads(record.details)
    assert "url_input_parameter_names" in details["indicator_names"]
    assert details["manual_review_required"] is True
    assert details["auto_confirmed"] is False
    assert details["network_requests_made"] == 0
    assert finding.status == "potential"


def test_unrelated_openapi_fields_do_not_create_ssrf_finding(db):
    project = _approved_project(db)
    metadata = {
        "identity_parameter_names": [],
        "sensitive_parameter_names": [],
        "url_input_parameter_names": [],
        "url_input_body_field_names": [],
        "request_body_field_names": ["description", "displayName"],
        "request_body_required": False,
        "security_declared": True,
        "security_explicitly_empty": False,
        "security_requirement_names": ["bearerAuth"],
        "available_security_scheme_names": ["bearerAuth"],
    }
    engine._record_openapi_operation_assessment(
        db, project.id, "https://example.com/api/profile",
        "POST", "/api/profile", "updateProfile", metadata,
    )
    assert db.scalar(select(Finding).where(
        Finding.project_id == project.id,
        Finding.title == "Potential server-side URL fetch input (SSRF review)",
    )) is None
