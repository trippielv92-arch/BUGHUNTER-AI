
"""Safe metadata-driven vulnerability assessment scenario planner."""
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode


def _metadata(notes):
    text = str(notes or "")
    marker = "OpenAPI metadata: "
    if marker not in text:
        return {}
    raw = text.split(marker, 1)[1].split(
        ". Names and declarations only", 1
    )[0]
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _safe_url(value):
    try:
        p = urlsplit(str(value or ""))
        query = [(k, "[REDACTED]") for k, _ in parse_qsl(
            p.query, keep_blank_values=True, max_num_fields=200
        )]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ""))
    except (ValueError, TypeError):
        return "[Target unavailable]"


def build_assessment_scenarios(endpoints):
    """Create manual review plans only; never performs network requests."""
    scenarios = []

    for endpoint in endpoints:
        url = str(endpoint.url or "")
        parsed = urlsplit(url)
        path = parsed.path.lower()
        method = str(endpoint.method or "GET").upper()
        meta = _metadata(endpoint.notes)

        identity = list(meta.get("identity_parameter_names", []))
        sensitive = list(meta.get("sensitive_parameter_names", []))
        body = list(meta.get("request_body_field_names", []))
        query = [k for k, _ in parse_qsl(
            parsed.query, keep_blank_values=True, max_num_fields=200
        )]
        names = {str(x).lower() for x in identity + sensitive + body + query}
        path_ids = re.findall(r"\{([^{}]+)\}", parsed.path)
        has_id = bool(identity or path_ids)
        writable = method in {"POST", "PUT", "PATCH"}
        auth = any(x in path for x in (
            "auth", "login", "logout", "token", "session",
            "password", "register", "reset", "mfa", "otp"
        ))
        payment = any(x in path for x in (
            "payment", "checkout", "invoice", "order", "transfer",
            "wallet", "refund", "coupon", "price", "quantity"
        ))
        file_route = any(x in path for x in (
            "upload", "download", "attachment", "document", "file", "media"
        ))
        url_input = any(x in names for x in (
            "url", "uri", "callback", "webhook", "redirect",
            "redirect_uri", "return_url", "image_url", "fetch_url"
        ))
        target = _safe_url(url)

        try:
            from app.services.endpoint_intelligence import analyze_endpoint
            intel = analyze_endpoint(endpoint) or {}
            priority = intel.get("priority_band", "Review")
        except Exception:
            priority = "Review"

        def add(category, title, trigger, steps, evidence):
            scenarios.append({
                "scenario_id": f"endpoint-{endpoint.id}-{len(scenarios)+1}",
                "endpoint_id": endpoint.id,
                "method": method,
                "target": target,
                "category": category,
                "title": title,
                "review_priority": priority,
                "trigger": trigger,
                "safe_steps": steps,
                "evidence_to_record": evidence,
                "automation_mode": "Manual / non-destructive",
                "status": "Planned — manual review required",
            })

        evidence = [
            "Approved target and endpoint",
            "Expected versus observed behavior",
            "Reproducible steps and timestamp",
            "Redacted evidence reference",
            "Test-account context and limitations",
        ]

        if has_id:
            add(
                "Authorization",
                "Object ownership and resource relationship authorization",
                "Identifier parameters or resource path placeholders detected.",
                [
                    "Use only researcher-controlled accounts and records.",
                    "Review ownership and parent-child access requirements.",
                    "Compare expected access with observed access using read-only checks.",
                    "Never access real users' records or change another account's data.",
                ], evidence
            )

        if auth or sensitive:
            add(
                "Authentication",
                "Authentication enforcement and credential handling",
                "Authentication route or sensitive parameter names detected.",
                [
                    "Review documented authentication requirements.",
                    "Compare authorized test-account behavior with documented policy.",
                    "Check that credentials are not exposed in URLs or logs.",
                    "Never collect or store real passwords, tokens, or session cookies.",
                ], evidence
            )

        if writable and (body or identity):
            add(
                "API Security",
                "Writable-field and mass-assignment authorization review",
                "Writable HTTP method and documented fields detected.",
                [
                    "Review documented writable fields and server-side allowlists.",
                    "Use only a controlled test record and permitted fields.",
                    "Review protection of ownership, role, price, and status fields.",
                    "Do not alter real transactions or other users' records.",
                ], evidence
            )

        if url_input:
            add(
                "SSRF",
                "Server-side URL fetching and destination validation",
                "URL, callback, webhook, or redirect parameter detected.",
                [
                    "Review whether the application fetches or follows supplied URLs.",
                    "Inspect destination allowlists and redirect validation.",
                    "Use only a program-approved researcher-controlled canary if permitted.",
                    "Never target private networks, metadata services, or third parties.",
                ], evidence
            )

        if query or body:
            add(
                "Input Validation",
                "Input validation and injection-resistance review",
                "Query parameters or documented body fields detected.",
                [
                    "Review input validation, typing, and output encoding.",
                    "Review parameterized database access and safe handling.",
                    "Use benign boundary values only in an authorized test environment.",
                    "Do not execute commands or destructive payloads.",
                ], evidence
            )

        if file_route:
            add(
                "File Handling",
                "File upload, download, and storage authorization review",
                "The endpoint path suggests file handling.",
                [
                    "Review allowed file types, size limits, and storage controls.",
                    "Use harmless files in an authorized test account.",
                    "Review download ownership and access-control requirements.",
                    "Do not upload executable content or access other users' files.",
                ], evidence
            )

        if payment:
            add(
                "Business Logic",
                "Payment and transaction workflow integrity review",
                "The endpoint path suggests a financial or order workflow.",
                [
                    "Map documented workflow states and permitted transitions.",
                    "Use sandbox accounts and test transactions only.",
                    "Review server-side price, quantity, ownership, and state validation.",
                    "Never initiate real payments, transfers, or refunds.",
                ], evidence
            )

        if sensitive:
            add(
                "Privacy",
                "Sensitive data minimization and exposure review",
                "Sensitive parameter names detected in endpoint metadata.",
                [
                    "Review whether sensitive fields are necessary.",
                    "Check access controls and redaction in responses and logs.",
                    "Use synthetic data only.",
                    "Do not collect real credentials or personal information.",
                ], evidence
            )

        if auth or payment or writable or "search" in path:
            add(
                "API Security",
                "Rate-limit and abuse-control policy review",
                "Authentication, transaction, write, or search route detected.",
                [
                    "Review documented rate limits and abuse controls first.",
                    "Inspect configuration and existing evidence before testing.",
                    "Only perform low-volume checks if explicitly authorized.",
                    "Stop if service degradation or unexpected impact occurs.",
                ], evidence
            )

    return scenarios
