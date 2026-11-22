"""Local endpoint classification and review-priority heuristics.

This module performs no network requests. It analyzes endpoint metadata only.
Query parameter values are deliberately excluded from its output.
"""

import json

from urllib.parse import parse_qsl, urlsplit, urlunsplit


SENSITIVE_PARAMETER_MARKERS = (
    "token", "secret", "password", "passwd", "credential",
    "session", "cookie", "api_key", "apikey", "access_key",
    "authorization", "auth", "private_key",
)

IDENTITY_PARAMETER_MARKERS = (
    "user_id", "userid", "account_id", "accountid",
    "customer_id", "customerid", "owner_id", "ownerid",
    "tenant_id", "tenantid", "role_id", "roleid",
)

URL_PARAMETER_NAMES = {
    "url", "uri", "link", "callback", "webhook",
    "redirect", "redirect_uri", "return_url", "next",
    "image_url", "fetch_url", "destination",
}


def _parameter_names(url):
    try:
        parsed = urlsplit(url or "")
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=200,
        )
    except (TypeError, ValueError):
        return []

    # Keep names only. Never return or retain query-string values.
    return sorted({
        str(name).strip().lower()
        for name, _value in pairs
        if name and str(name).strip()
    })


def safe_endpoint_url(url):
    """Return an endpoint URL with query values redacted."""
    try:
        parsed = urlsplit(url or "")
        if not parsed.query:
            return url or ""

        names = _parameter_names(url)
        if not names:
            query = "[query values redacted]"
        else:
            query = "&".join(
                f"{name}=REDACTED" for name in names
            )

        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            query,
            "",
        ))
    except (TypeError, ValueError):
        return "[endpoint URL unavailable]"



def _openapi_metadata_from_notes(notes):
    """Extract locally stored OpenAPI names and declarations only."""
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
        result = json.loads(notes[start:end])
    except (ValueError, TypeError):
        return {}

    return result if isinstance(result, dict) else {}


def analyze_endpoint(endpoint):
    """Return explainable classification and manual-review priority."""
    url = getattr(endpoint, "url", "") or ""
    method = (getattr(endpoint, "method", "GET") or "GET").upper()
    endpoint_type = (
        getattr(endpoint, "endpoint_type", "") or ""
    ).lower()
    notes = getattr(endpoint, "notes", "") or ""
    try:
        parsed = urlsplit(url)
        path = (parsed.path or "/").lower()
    except (TypeError, ValueError):
        path = "/"

    searchable = f"{path} {endpoint_type}".lower()
    names = _parameter_names(url)
    metadata = _openapi_metadata_from_notes(notes)

    classifications = []
    signals = []
    score = 0

    def classify(name):
        if name not in classifications:
            classifications.append(name)

    def signal(points, description):
        nonlocal score
        score += points
        signals.append(description)

    def metadata_names(key):
        value = metadata.get(key, [])
        if not isinstance(value, list):
            return []
        return sorted({
            str(item).strip().lower()
            for item in value
            if isinstance(item, str) and item.strip()
        })

    identity_names = metadata_names("identity_parameter_names")
    sensitive_names = metadata_names("sensitive_parameter_names")
    body_names = metadata_names("request_body_field_names")

    # Also recognize identity and sensitive names inside request-body
    # schemas, not only URL parameters.
    all_identity_names = sorted(set(identity_names) | {
        name for name in body_names
        if any(marker in name for marker in IDENTITY_PARAMETER_MARKERS)
    })
    all_sensitive_names = sorted(set(sensitive_names) | {
        name for name in body_names
        if any(marker in name for marker in SENSITIVE_PARAMETER_MARKERS)
    })

    query_sensitive_names = [
        name for name in names
        if any(marker in name for marker in SENSITIVE_PARAMETER_MARKERS)
    ]
    query_identity_names = [
        name for name in names
        if any(marker in name for marker in IDENTITY_PARAMETER_MARKERS)
    ]
    url_names = [
        name for name in names
        if name in URL_PARAMETER_NAMES
        or name.endswith("_url")
        or name.endswith("_uri")
    ]

    is_api = (
        "api" in endpoint_type
        or path.startswith("/api/")
        or "/graphql" in path
        or "graphql" in endpoint_type
    )
    is_auth = any(word in f"{path} {searchable}" for word in (
        "login", "signin", "sign-in", "authenticate",
        "password", "reset", "register", "signup", "mfa",
        "oauth", "authorize", "token",
    ))
    is_admin = any(word in f"{path} {searchable}" for word in (
        "admin", "administrator", "moderator", "manage",
    ))
    is_payment = any(word in f"{path} {searchable}" for word in (
        "payment", "checkout", "transaction", "transfer",
        "wallet", "order", "cart", "invoice", "billing", "price",
    ))
    # File classification must come from the actual route path.
    # Generic endpoint descriptions such as "OpenAPI documented API
    # operation" must not trigger file-handling classification.
    is_file = any(word in path for word in (
        "upload", "download", "attachment", "file",
        "document", "export", "import",
    ))
    is_search = any(word in f"{path} {searchable}" for word in (
        "search", "filter", "sort", "lookup",
    ))
    is_write = method in {"POST", "PUT", "PATCH", "DELETE"}

    if is_api:
        classify("API")
        signal(15, "API-style endpoint")
    if is_auth:
        classify("Authentication")
        signal(15, "Authentication-related route")
    if is_admin:
        classify("Administration")
        signal(20, "Administrative route")
    if is_payment:
        classify("Payments / business logic")
        signal(20, "Payment or business-logic route")
    if is_file:
        classify("File handling")
        signal(15, "File-handling route")
    if is_search:
        classify("Search / filtering")
        signal(5, "Search or filtering route")

    if is_write:
        signal(15, "State-changing HTTP method")

    if names:
        signal(5, "Query parameters are present")

    if query_sensitive_names:
        signal(15, "Sensitive-looking query parameter names")
    if query_identity_names:
        signal(10, "Object or account identifier query parameters")
    if url_names:
        classify("URL handling")
        signal(15, "URL, redirect or callback parameter names")

    # OpenAPI-specific evidence signals.
    if metadata:
        classify("Documented API schema")
        signal(5, "OpenAPI operation metadata available")

    if all_identity_names:
        signal(
            12,
            "OpenAPI documents object or account identifier fields",
        )

    if all_sensitive_names:
        signal(
            12,
            "OpenAPI documents sensitive-looking parameter or body fields",
        )

    if is_write and body_names:
        signal(
            10,
            "Writable operation has documented request-body fields",
        )

    security_declared = metadata.get("security_declared")
    security_empty = metadata.get("security_explicitly_empty")

    if metadata and (
        security_declared is False or security_empty is True
    ):
        signal(
            8,
            "OpenAPI operation has no declared security requirement",
        )

    if not classifications:
        classify("General web")

    score = min(score, 100)

    if score >= 70:
        band = "Critical review priority"
    elif score >= 50:
        band = "High review priority"
    elif score >= 25:
        band = "Medium review priority"
    else:
        band = "Low review priority"

    return {
        "classification": ", ".join(classifications),
        "classifications": classifications,
        "priority_score": score,
        "priority_band": band,
        "signals": signals,
        "signals_summary": "; ".join(signals) if signals else (
            "No elevated metadata signals detected"
        ),
        "parameter_names": names,
        "sensitive_parameter_names": sorted(
            set(query_sensitive_names) | set(all_sensitive_names)
        ),
        "identity_parameter_names": sorted(
            set(query_identity_names) | set(all_identity_names)
        ),
        "url_parameter_names": url_names,
        "openapi_body_field_names": body_names,
        "openapi_security_declared": security_declared,
        "openapi_security_explicitly_empty": security_empty,
        "priority_note": (
            "Heuristic manual-review priority only; not a vulnerability "
            "finding, exploitability score or severity rating. OpenAPI "
            "signals describe documented names and declarations only."
        ),
    }
