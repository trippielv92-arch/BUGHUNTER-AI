import json
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import urlsplit, parse_qsl

from sqlalchemy import select

from app.models.entities import (
    Project, ScopeAsset, Endpoint, TestCase, Activity
)
from app.services.projects import require_active_project


OWASP_TESTS = [
    ("Authorization", "Horizontal access control"),
    ("Authorization", "Vertical access control"),
    ("Authentication", "Login and account recovery"),
    ("Authentication", "Multi-factor authentication"),
    ("Session Management", "Session rotation"),
    ("Session Management", "Logout invalidation"),
    ("Session Management", "Cookie security"),
    ("Input Validation", "Reflected input handling"),
    ("Input Validation", "Stored input handling"),
    ("Input Validation", "HTML output encoding"),
    ("Injection", "SQL injection indicators"),
    ("Injection", "Command injection indicators"),
    ("File Handling", "File upload validation"),
    ("File Handling", "File download authorization"),
    ("SSRF", "Server-side URL fetching"),
    ("API Security", "Object-level authorization"),
    ("API Security", "Function-level authorization"),
    ("API Security", "Mass assignment"),
    ("API Security", "Rate-limit behavior"),
    ("CORS", "Cross-origin policy"),
    ("Configuration", "Security headers"),
    ("Configuration", "TLS configuration"),
    ("Business Logic", "Workflow enforcement"),
    ("Business Logic", "Price and quantity validation"),
    ("Business Logic", "Race conditions"),
    ("Client-side Security", "DOM input handling"),
    ("Client-side Security", "Sensitive data exposure"),
    ("Privacy", "Sensitive information in responses"),
    ("Redirects", "Redirect destination validation"),
    ("Logging", "Sensitive data in errors and logs"),
]


def log(db, project_id, event, details=""):
    db.add(Activity(
        project_id=project_id,
        event=event,
        details=details
    ))
    db.commit()



def _normalize_scope_host(host):
    host = (host or "").strip().lower().rstrip(".")

    if not host or len(host) > 253:
        raise ValueError("Invalid target hostname.")

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid internationalized hostname.")

    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid target hostname.")

    return host


def validate_target(db, project_id, url):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("Enter a valid target URL.")

    if url != url.strip() or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("Target URL contains invalid whitespace or control characters.")

    try:
        parsed = urlsplit(url)
        host = _normalize_scope_host(parsed.hostname)

        if parsed.port is not None:
            expected_port = 443 if parsed.scheme.lower() == "https" else 80
            if parsed.port != expected_port:
                raise ValueError("Only standard HTTP and HTTPS ports are permitted.")

    except ValueError as exc:
        if str(exc).startswith(("Only standard", "Invalid target")):
            raise
        raise ValueError("Malformed target URL.") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are permitted.")

    if not parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials or malformed authority are not permitted.")

    if parsed.fragment:
        raise ValueError("Remove the URL fragment before assessment.")

    project = require_active_project(db, project_id)

    if not project.scope_approved:
        raise ValueError("Project scope has not been approved.")

    assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project_id,
            ScopeAsset.included.is_(True),
            ScopeAsset.approved.is_(True)
        )
    ).all()

    allowed = False
    for asset in assets:
        try:
            if host == _normalize_scope_host(asset.host):
                allowed = True
                break
        except ValueError:
            continue

    if not allowed:
        raise ValueError("URL is outside approved project scope.")

    return parsed



# Endpoint intelligence is recommendation-only. It never sends requests,
# executes payloads, or changes a test case's assessment status.

def _openapi_metadata_from_notes(notes):
    """Read only the bounded metadata JSON stored by OpenAPI discovery."""
    notes = str(notes or "")
    marker = "OpenAPI metadata: "
    ending = ". Names and declarations only"

    start = notes.find(marker)
    if start < 0:
        return {}

    start += len(marker)
    end = notes.find(ending, start)
    if end < 0:
        return {}

    try:
        metadata = json.loads(notes[start:end])
    except (ValueError, TypeError):
        return {}

    return metadata if isinstance(metadata, dict) else {}


def _authorization_relationship_context(endpoint):
    """Extract route and documented identity relationships without requests."""
    parsed = urlsplit(endpoint.url or "")
    path = parsed.path or "/"
    segments = [part for part in path.strip("/").split("/") if part]

    metadata = _openapi_metadata_from_notes(endpoint.notes)
    names = set()

    for segment in segments:
        if segment.startswith("{") and segment.endswith("}"):
            names.add(segment[1:-1])

    for field in ("identity_parameter_names",):
        values = metadata.get(field, [])
        if isinstance(values, list):
            names.update(str(value)[:120] for value in values)

    normalized = {
        "".join(ch for ch in name.lower() if ch.isalnum())
        for name in names
    }
    lower_segments = {segment.lower() for segment in segments}

    nested = any(
        segment.startswith("{")
        and segment.endswith("}")
        and index < len(segments) - 1
        for index, segment in enumerate(segments)
    )

    return {
        "path": path,
        "parameter_names": sorted(names)[:30],
        "nested_resource": nested,
        "tenant_boundary": bool(normalized & {
            "tenantid", "organizationid", "orgid",
            "workspaceid", "companyid",
        }),
        "role_boundary": bool(normalized & {
            "roleid", "permissionid", "privilegeid",
        }) or bool(lower_segments & {
            "admin", "admins", "administrator",
            "administrators", "roles", "permissions", "privileges",
        }),
    }


def _endpoint_test_recommendations(endpoint):
    parsed = urlsplit(endpoint.url)
    path = (parsed.path or "/").lower()
    endpoint_type = (endpoint.endpoint_type or "").lower()
    method = (endpoint.method or "GET").upper()
    query_names = {
        key.lower() for key, _ in parse_qsl(
            parsed.query, keep_blank_values=True
        )
    }
    text = path + " " + endpoint_type + " " + (endpoint.notes or "").lower()
    recommendations = set()
    metadata = _openapi_metadata_from_notes(endpoint.notes)

    def add(category, title):
        recommendations.add((category, title))

    is_api = (
        "api" in endpoint_type
        or path.startswith("/api/")
        or "/graphql" in path
        or "application" in endpoint_type
    )
    is_write = method in {"POST", "PUT", "PATCH", "DELETE"}

    if is_api:
        add("API Security", "Object-level authorization")
        add("API Security", "Function-level authorization")
        add("API Security", "Rate-limit behavior")
        add("CORS", "Cross-origin policy")

        if is_write:
            add("API Security", "Mass assignment")

    # OpenAPI-derived recommendations are more specific than generic
    # endpoint heuristics. They remain manual assessment tasks.
    identity_names = metadata.get("identity_parameter_names", [])
    sensitive_names = metadata.get("sensitive_parameter_names", [])
    body_fields = metadata.get("request_body_field_names", [])

    if isinstance(identity_names, list) and identity_names:
        add(
            "API Security",
            "Object-level authorization for documented identifiers",
        )

    if is_write and isinstance(body_fields, list) and body_fields:
        add(
            "API Security",
            "Mass assignment review for documented body fields",
        )

    if (
        metadata.get("security_explicitly_empty") is True
        or metadata.get("security_declared") is False
    ):
        add(
            "Authentication",
            "Authentication enforcement for operation without declared security",
        )

    if isinstance(sensitive_names, list) and sensitive_names:
        add(
            "API Security",
            "Sensitive parameter handling for documented parameters",
        )

    if any(word in text for word in (
        "login", "signin", "sign-in", "authenticate",
        "password", "reset-password", "forgot-password",
        "register", "signup", "sign-up", "mfa", "2fa",
    )):
        add("Authentication", "Login and account recovery")
        add("Authentication", "Multi-factor authentication")
        add("Session Management", "Session rotation")
        add("Session Management", "Cookie security")

    if any(word in text for word in ("logout", "signout", "sign-out")):
        add("Session Management", "Logout invalidation")
        add("Session Management", "Cookie security")

    if any(word in text for word in (
        "admin", "administrator", "manage", "moderator",
    )):
        add("Authorization", "Vertical access control")
        add("API Security", "Function-level authorization")

    if any(word in text for word in (
        "upload", "attachment", "import-file", "media",
    )):
        add("File Handling", "File upload validation")

    if any(word in text for word in (
        "download", "export", "document", "attachment",
    )):
        add("File Handling", "File download authorization")

    if query_names:
        add("Input Validation", "Reflected input handling")
        add("Input Validation", "HTML output encoding")
        add("Injection", "SQL injection indicators")

    if any(key in query_names for key in (
        "url", "uri", "link", "callback", "fetch", "image_url",
    )) or any(word in text for word in ("webhook", "proxy", "fetch-url")):
        add("SSRF", "Server-side URL fetching")

    if any(key in query_names for key in (
        "next", "return", "return_url", "redirect", "redirect_uri",
    )) or any(word in text for word in ("redirect", "callback")):
        add("Redirects", "Redirect destination validation")

    if any(word in text for word in (
        "payment", "checkout", "transaction", "transfer",
        "wallet", "order", "cart", "price", "invoice",
    )):
        add("Business Logic", "Workflow enforcement")
        add("Business Logic", "Price and quantity validation")
        add("Business Logic", "Race conditions")

    if any(word in text for word in (
        "search", "query", "filter", "sort", "lookup",
    )):
        add("Input Validation", "Reflected input handling")
        add("Injection", "SQL injection indicators")

    if "web page" in endpoint_type or endpoint_type in {
        "login", "registration", "password recovery",
    }:
        add("Configuration", "Security headers")
        add("Configuration", "TLS configuration")
        add("Session Management", "Cookie security")

    if is_api and is_write:
        add("Business Logic", "Workflow enforcement")

    relationship = _authorization_relationship_context(endpoint)

    if relationship["nested_resource"]:
        add(
            "API Security",
            "Nested-resource ownership and parent-child authorization",
        )

    if relationship["tenant_boundary"]:
        add(
            "API Security",
            "Tenant and organization boundary authorization",
        )

    if relationship["role_boundary"]:
        add(
            "Authorization",
            "Role and privileged-function authorization",
        )

    return sorted(recommendations)


def _manual_assessment_worksheet(category, title, endpoint):
    """Build a safe, metadata-led worksheet; never performs a test."""
    title_lower = (title or "").lower()
    method = (endpoint.method or "GET").upper()

    common = [
        "1. Confirm the exact host and endpoint are explicitly approved.",
        "2. Use only test accounts, roles and records you control or are authorized to assess.",
        "3. Prefer read-only observations. Do not change, delete, transfer or expose real-user data.",
        "4. Record the expected behavior before comparing it with the observed behavior.",
        "5. Redact credentials, tokens, personal data and response values in all evidence.",
        "6. If the required test accounts or authorization are unavailable, mark the task Blocked or Needs review.",
    ]

    specific = [
        "Purpose: assess whether the application enforces the documented access boundary.",
    ]

    if "nested-resource" in title_lower or "parent-child" in title_lower:
        specific = [
            "Purpose: review whether a child resource is correctly bound to its parent.",
            "1. Identify a parent and child record created for your authorized test account.",
            "2. Record the expected parent-child ownership relationship.",
            "3. Using only controlled test fixtures, review whether the application checks both the parent and child relationship.",
            "4. Do not substitute identifiers belonging to real users or attempt to retrieve their records.",
            "5. Record whether the relationship is enforced, unclear, or not testable.",
        ]
    elif "tenant" in title_lower or "organization boundary" in title_lower:
        specific = [
            "Purpose: review tenant or organization isolation.",
            "1. Use two tenant contexts that you own or are explicitly authorized to test.",
            "2. Record which test account belongs to each tenant and which records are fixtures.",
            "3. Review documented access rules and compare them with behavior in those controlled contexts.",
            "4. Do not access another organization's real data or alter tenant membership.",
            "5. Record the access decision and any evidence with identifiers and sensitive values redacted.",
        ]
    elif "role" in title_lower or "privileged-function" in title_lower:
        specific = [
            "Purpose: review role-based access to privileged functions.",
            "1. Identify the authorized test roles and the documented permissions for each.",
            "2. Use only test accounts provisioned for those roles.",
            "3. Compare the documented permission with the application's access decision.",
            "4. Do not grant privileges, modify roles, or invoke state-changing operations without explicit authorization.",
            "5. Record the role, expected permission, observed decision and limitations.",
        ]
    elif "object-level authorization" in title_lower:
        specific = [
            "Purpose: review ownership checks for object identifiers.",
            "1. Identify records created specifically for your authorized test account.",
            "2. Record the expected owner and the documented access rule.",
            "3. Review the authorization decision using controlled fixtures only.",
            "4. Do not enumerate identifiers or access records belonging to real users.",
            "5. Record the decision and redacted evidence; distinguish a confirmed observation from an assumption.",
        ]
    elif "authentication enforcement" in title_lower:
        specific = [
            "Purpose: determine whether authentication is required by the application.",
            "1. Treat missing OpenAPI security declarations as a documentation observation, not proof of missing authentication.",
            "2. Check the documented intended access level and any global or inherited security controls.",
            "3. Review behavior only with an authorized test account and approved, non-sensitive test data.",
            "4. Do not attempt credential bypass or access protected real-user information.",
            "5. Record whether authentication is required, intentionally not required, or remains unclear.",
        ]
    elif "mass assignment" in title_lower:
        specific = [
            "Purpose: review whether writable fields are restricted to an approved allowlist.",
            "1. Compare documented request-body fields with the application's intended writable fields.",
            "2. Identify fields that should be server-controlled, such as ownership, role or privilege fields.",
            "3. Review server-side validation and assignment logic where source code or documentation is available.",
            "4. Do not submit unexpected fields or alter privileges without explicit authorization and a controlled test environment.",
            "5. Record the field names and reasoning; never include secret values.",
        ]
    elif "sensitive parameter" in title_lower:
        specific = [
            "Purpose: review handling of parameters whose names suggest sensitive values.",
            "1. Identify the parameter names from endpoint metadata; do not copy example secrets or values.",
            "2. Review whether values are appropriately protected, validated and excluded from logs or reports.",
            "3. Use only synthetic test values in an explicitly authorized environment.",
            "4. Redact all values from notes, screenshots and evidence.",
            "5. Record the control reviewed and any uncertainty.",
        ]

    lines = [
        "MANUAL ASSESSMENT WORKSHEET",
        f"Category: {category}",
        f"Operation: {method}",
        *specific,
        "Safety and evidence checklist:",
        *common,
        "Evidence to record: test context, expected result, observed result, timestamp, response status where applicable, redacted evidence reference, and limitations.",
        "Assessment rule: endpoint metadata and recommendations are leads for review, not evidence of a vulnerability. Do not mark a finding confirmed without independent verification.",
    ]
    return "\n".join(lines)


def recommend_endpoint_tests(db, project_id, endpoint_id=None):
    """
    Create deduplicated, endpoint-targeted manual assessment tasks.

    Returns the number of newly created TestCase records.
    """
    project = require_active_project(db, project_id)
    if not project.scope_approved:
        raise ValueError(
            "Approve project scope before generating endpoint assessments."
        )

    statement = select(Endpoint).where(
        Endpoint.project_id == project_id
    )
    if endpoint_id is not None:
        statement = statement.where(Endpoint.id == endpoint_id)

    endpoints = db.scalars(statement.order_by(Endpoint.id)).all()
    created = 0

    for endpoint in endpoints:
        # Revalidate every target before assigning an assessment task.
        validate_target(db, project_id, endpoint.url)

        for category, title in _endpoint_test_recommendations(endpoint):
            existing_id = db.scalar(
                select(TestCase.id).where(
                    TestCase.project_id == project_id,
                    TestCase.category == category,
                    TestCase.title == title,
                    TestCase.target == endpoint.url,
                ).limit(1)
            )
            if existing_id:
                continue

            db.add(TestCase(
                project_id=project_id,
                category=category,
                title=title,
                target=endpoint.url,
                status="Planned",
                notes=(
                    "Automatically recommended from endpoint metadata. "
                    "This is a manual assessment task, not a vulnerability "
                    "finding. Verify authorization and test boundaries before "
                    "any active assessment. Record methodology, evidence, "
                    "impact and limitations. No requests or payloads were "
                    "sent to create this recommendation. "
                    + (
                        "OpenAPI evidence: "
                        + (
                            "identity parameter names: "
                            + ", ".join(
                                str(x)[:120] for x in
                                _openapi_metadata_from_notes(
                                    endpoint.notes
                                ).get("identity_parameter_names", [])[:20]
                            ) + "; "
                            if title.startswith(
                                "Object-level authorization for documented"
                            ) else ""
                        )
                        + (
                            "request-body field names: "
                            + ", ".join(
                                str(x)[:120] for x in
                                _openapi_metadata_from_notes(
                                    endpoint.notes
                                ).get("request_body_field_names", [])[:30]
                            ) + "; "
                            if title.startswith(
                                "Mass assignment review for documented"
                            ) else ""
                        )
                        + (
                            "sensitive-looking parameter names: "
                            + ", ".join(
                                str(x)[:120] for x in
                                _openapi_metadata_from_notes(
                                    endpoint.notes
                                ).get("sensitive_parameter_names", [])[:20]
                            ) + "; "
                            if title.startswith(
                                "Sensitive parameter handling"
                            ) else ""
                        )
                        + (
                            "The API document did not declare an operation "
                            "security requirement; verify whether the operation "
                            "is intentionally public and whether authentication "
                            "is enforced by another mechanism. "
                            if title.startswith(
                                "Authentication enforcement for operation"
                            ) else ""
                        )
                    )
                ) + "\n\n" + _manual_assessment_worksheet(
                    category, title, endpoint
                ),
            ))
            created += 1

    if created:
        db.flush()

    return created


def add_endpoint(db, project_id, url, endpoint_type, method, notes=""):
    validate_target(db, project_id, url)

    endpoint = Endpoint(
        project_id=project_id,
        url=url.strip(),
        endpoint_type=endpoint_type,
        method=method,
        notes=notes
    )

    db.add(endpoint)
    db.flush()

    recommend_endpoint_tests(db, project_id, endpoint.id)

    db.commit()
    db.refresh(endpoint)

    log(db, project_id, "Endpoint registered", url)

    return endpoint


def initialize_test_plan(db, project_id):
    require_active_project(db, project_id)

    existing = db.scalar(
        select(TestCase.id).where(
            TestCase.project_id == project_id
        ).limit(1)
    )

    if existing:
        return 0

    for category, title in OWASP_TESTS:
        db.add(TestCase(
            project_id=project_id,
            category=category,
            title=title,
            status="Planned",
            notes="Manual review required. Record methodology, evidence and limitations."
        ))

    db.commit()

    log(
        db,
        project_id,
        "OWASP test plan initialized",
        f"{len(OWASP_TESTS)} test cases"
    )

    return len(OWASP_TESTS)


def update_test_case(
    db,
    project_id,
    test_id,
    status,
    target="",
    notes="",
    commit=True,
):
    allowed = [
        "Planned",
        "In progress",
        "Needs review",
        "Finding identified",
        "Passed",
        "Blocked",
        "Not applicable"
    ]

    if status not in allowed:
        raise ValueError("Invalid test status.")

    require_active_project(db, project_id)

    test = db.get(TestCase, test_id)

    if not test or test.project_id != project_id:
        raise ValueError("Test case not found in this project.")

    if target:
        validate_target(db, project_id, target)

    # Preserve the generated manual worksheet if the editor submission
    # accidentally omits it. Assessment results remain in the same notes
    # field so existing report exporters continue to include them.
    existing_notes = test.notes or ""
    submitted_notes = notes or ""
    worksheet_marker = "MANUAL ASSESSMENT WORKSHEET"

    if worksheet_marker in existing_notes and worksheet_marker not in submitted_notes:
        worksheet_start = existing_notes.index(worksheet_marker)
        result_marker = existing_notes.find(
            "\nASSESSMENT RESULT", worksheet_start
        )
        worksheet_end = (
            result_marker if result_marker >= 0 else len(existing_notes)
        )
        worksheet = existing_notes[worksheet_start:worksheet_end].rstrip()
        submitted_notes = (
            worksheet + "\n\n" + submitted_notes.lstrip()
        ).strip()

    test.status = status
    test.target = target
    test.notes = submitted_notes
    test.updated_at = datetime.now(timezone.utc)

    if commit:
        db.commit()

        log(
            db,
            project_id,
            "Test case updated",
            f"{test.title}: {status}"
        )

    return test
