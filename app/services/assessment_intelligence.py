"""Vulnerability-specific assessment intelligence.

Recommendations are manual review guidance, not vulnerability findings.
This module performs no network requests and executes no payloads.
"""

import json
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from app.services.endpoint_intelligence import analyze_endpoint


STATUSES = {
    "planned",
    "in progress",
    "needs review",
    "finding identified",
    "passed",
    "blocked",
    "not applicable",
}

IDENTITY_NAMES = {
    "userid", "accountid", "customerid", "ownerid", "tenantid",
    "organizationid", "orgid", "roleid", "memberid", "profileid",
    "resourceid", "projectid", "orderid", "invoiceid",
}

SENSITIVE_NAMES = {
    "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "authorization",
    "credential", "session", "private_key", "cookie",
}

URL_NAMES = {
    "url", "uri", "link", "callback", "webhook", "redirect",
    "redirect_uri", "return_url", "next", "image_url",
    "fetch_url", "destination",
}

FILE_WORDS = {
    "file", "upload", "download", "attachment", "document",
    "export", "import", "media", "avatar",
}

PAYMENT_WORDS = {
    "payment", "pay", "checkout", "billing", "invoice",
    "transaction", "wallet", "refund", "price", "order",
}

AUTH_WORDS = {
    "login", "logout", "signin", "signout", "auth",
    "session", "password", "token", "register", "account",
}

ADMIN_WORDS = {
    "admin", "administrator", "roles", "permissions",
    "privileges", "settings", "management",
}


def _metadata(notes):
    text = str(notes or "")
    marker = "OpenAPI metadata: "
    start = text.find(marker)
    if start < 0:
        return {}

    start += len(marker)
    end = text.find(". Names and declarations only", start)
    if end < 0:
        return {}

    try:
        value = json.loads(text[start:end])
    except (ValueError, TypeError):
        return {}

    return value if isinstance(value, dict) else {}


def _names(metadata, key):
    value = metadata.get(key, [])
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {
        re.sub(r"[^a-z0-9_]", "", str(item).lower())
        for item in list(value)[:200]
        if str(item).strip()
    }


def _endpoint_context(endpoint):
    raw_url = str(getattr(endpoint, "url", "") or "")
    try:
        parsed = urlsplit(raw_url)
        path = parsed.path.lower()
        query_names = {
            key.lower()
            for key, _ in parse_qsl(
                parsed.query, keep_blank_values=True, max_num_fields=200
            )
        }
    except (ValueError, TypeError):
        path = ""
        query_names = set()

    method = str(getattr(endpoint, "method", "GET") or "GET").upper()
    endpoint_type = str(
        getattr(endpoint, "endpoint_type", "") or ""
    ).lower()

    metadata = _metadata(getattr(endpoint, "notes", ""))
    identity = _names(metadata, "identity_parameter_names")
    sensitive = _names(metadata, "sensitive_parameter_names")
    body = _names(metadata, "request_body_field_names")

    segments = {
        part.lower()
        for part in re.split(r"[/_.{}-]+", path)
        if part
    }
    all_names = query_names | identity | sensitive | body

    return {
        "path": path,
        "method": method,
        "segments": segments,
        "query_names": query_names,
        "identity": identity,
        "sensitive": sensitive,
        "body": body,
        "all_names": all_names,
        "metadata": metadata,
        "is_api": (
            path.startswith("/api")
            or path == "/graphql"
            or "api" in endpoint_type
            or "openapi" in endpoint_type
        ),
    }


def _scenario(category, title, trigger, priority, steps, evidence):
    return {
        "category": category,
        "title": title,
        "trigger": trigger,
        "priority": priority,
        "status": "Planned",
        "manual_only": True,
        "network_requests_by_planner": 0,
        "payloads_executed_by_planner": 0,
        "safe_steps": steps,
        "evidence_checklist": evidence,
    }


COMMON_STEPS = [
    "Confirm the target belongs to the explicitly approved project scope.",
    "Use only owner-provided staging systems and controlled test accounts.",
    "Prefer read-only observations; do not modify or delete real user data.",
    "Record expected and observed behavior, including limitations.",
]

COMMON_EVIDENCE = [
    "Record the endpoint and HTTP method.",
    "Record the test account role and controlled test-data context.",
    "Capture redacted observations and timestamps.",
    "Remove credentials, tokens, cookies and personal information.",
]


def _make_scenarios(endpoint, context):
    path = context["path"]
    segments = context["segments"]
    names = context["all_names"]
    method = context["method"]
    identity = context["identity"]
    sensitive = context["sensitive"]
    body = context["body"]

    output = []

    def add(category, title, trigger, priority="Medium"):
        output.append(_scenario(
            category, title, trigger, priority,
            COMMON_STEPS.copy(), COMMON_EVIDENCE.copy()
        ))

    if identity or re.search(r"\{[^/{}]+\}", path):
        add(
            "Authorization",
            "Object ownership and identifier authorization",
            "Identifiers or resource placeholders are present.",
            "High",
        )

    if (
        identity & {"tenantid", "organizationid", "orgid"}
        or segments & {"tenant", "tenants", "organization", "organizations"}
    ):
        add(
            "Authorization",
            "Tenant and organization isolation",
            "Tenant or organization identifiers are present.",
            "High",
        )

    if (
        segments & ADMIN_WORDS
        or identity & {"roleid", "permissionid", "privilegeid"}
    ):
        add(
            "Authorization",
            "Role and privileged-function authorization",
            "Administrative route or role-related identifier detected.",
            "High",
        )

    if segments & AUTH_WORDS or sensitive:
        add(
            "Authentication",
            "Authentication enforcement and credential handling",
            "Authentication route or sensitive parameter metadata detected.",
            "High",
        )

    if context["is_api"] and method in {"POST", "PUT", "PATCH"} and body:
        add(
            "API Security",
            "Writable-field and mass-assignment authorization review",
            "Writable API operation has documented body fields.",
            "High",
        )

    if context["is_api"]:
        add(
            "API Security",
            "API function-level authorization and method policy",
            "API endpoint discovered.",
            "Medium",
        )

    if names & URL_NAMES:
        add(
            "SSRF",
            "Server-side URL fetching and redirect destination review",
            "URL, callback, webhook or redirect parameter name detected.",
            "High",
        )

    if segments & FILE_WORDS:
        add(
            "File Handling",
            "File access, upload and download authorization",
            "File-handling route detected.",
            "High",
        )

    if segments & PAYMENT_WORDS:
        add(
            "Business Logic",
            "Payment, price and transaction workflow integrity",
            "Payment or transaction route detected.",
            "High",
        )

    if context["query_names"] or body:
        add(
            "Input Validation",
            "Input validation and output encoding review",
            "Query or documented request-body fields are present.",
            "Medium",
        )

    if segments & {"search", "filter", "query"}:
        add(
            "Input Validation",
            "Search and filtering input handling",
            "Search or filtering route detected.",
            "Medium",
        )

    if sensitive:
        add(
            "Privacy",
            "Sensitive information minimization and response exposure",
            "Sensitive parameter names are documented.",
            "High",
        )

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        add(
            "Business Logic",
            "State-changing operation and workflow enforcement",
            "Endpoint declares a state-changing HTTP method.",
            "Medium",
        )

    if not output:
        add(
            "Configuration",
            "Security headers, transport and response configuration review",
            "General endpoint review.",
            "Low",
        )

    # Remove duplicate recommendations while retaining their original order.
    unique = {}
    for item in output:
        unique[(item["category"], item["title"])] = item

    return list(unique.values())


def _normalize_target(value):
    try:
        parsed = urlsplit(str(value or ""))
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port,
            parsed.path.rstrip("/") or "/",
        )
    except (ValueError, TypeError):
        return None


def _test_matches(test, endpoint):
    target = _normalize_target(getattr(test, "target", ""))
    endpoint_target = _normalize_target(getattr(endpoint, "url", ""))
    return target is not None and target == endpoint_target


def build_attack_surface_assessments(endpoints, test_cases=()):
    """Build per-endpoint recommendations and progress from existing records.

    URL matching is conservative. TestCase does not store an endpoint ID or
    method, so this function explicitly reports that limitation.
    """
    tests = list(test_cases or ())
    results = []

    for endpoint in endpoints:
        context = _endpoint_context(endpoint)
        recommendations = _make_scenarios(endpoint, context)

        try:
            intelligence = analyze_endpoint(endpoint) or {}
        except Exception:
            intelligence = {}

        matching_tests = [
            test for test in tests if _test_matches(test, endpoint)
        ]

        status_counts = Counter(
            str(getattr(test, "status", "Planned") or "Planned").lower()
            for test in matching_tests
        )

        for scenario in recommendations:
            related = [
                test for test in matching_tests
                if str(getattr(test, "category", "")).lower()
                   == scenario["category"].lower()
                and str(getattr(test, "title", "")).lower()
                   == scenario["title"].lower()
            ]

            if related:
                scenario["status"] = str(
                    getattr(related[-1], "status", "Planned") or "Planned"
                )
                scenario["test_case_ids"] = [
                    getattr(test, "id", None) for test in related
                ]
            else:
                scenario["test_case_ids"] = []

        applicable = [
            item for item in recommendations
            if item["status"].lower() != "not applicable"
        ]
        completed = sum(
            item["status"].lower() in {"passed", "finding identified"}
            for item in applicable
        )

        safe_url = str(getattr(endpoint, "url", "") or "").split("?", 1)[0]
        results.append({
            "endpoint_id": getattr(endpoint, "id", None),
            "url": safe_url,
            "method": context["method"],
            "endpoint_type": getattr(endpoint, "endpoint_type", ""),
            "classification": intelligence.get("classification", "Unclassified"),
            "priority_band": intelligence.get("priority_band", "Review"),
            "priority_score": intelligence.get("priority_score", 0),
            "recommendations": recommendations,
            "recommendation_count": len(recommendations),
            "assessment_completed": completed,
            "assessment_total": len(applicable),
            "assessment_percent": (
                round(completed * 100 / len(applicable))
                if applicable else 0
            ),
            "status_counts": dict(status_counts),
            "matched_test_case_count": len(matching_tests),
            "matching_limitation": (
                "Existing test cases are matched by URL, not endpoint ID "
                "or HTTP method."
            ),
        })

    totals = Counter()
    for result in results:
        totals["endpoints"] += 1
        totals["recommendations"] += result["recommendation_count"]
        totals["completed"] += result["assessment_completed"]
        totals["applicable"] += result["assessment_total"]

    totals["completion_percent"] = (
        round(totals["completed"] * 100 / totals["applicable"])
        if totals["applicable"] else 0
    )

    return {
        "endpoints": results,
        "summary": dict(totals),
        "manual_only": True,
        "network_requests_made": 0,
        "payloads_executed": 0,
    }
