"""
BugHunter AI - Autonomous Website Analysis Engine

Initial capabilities:
- Approved HTTPS target validation
- Sequential, rate-limited page discovery
- Same-host HTML link crawling
- robots.txt awareness
- HTTP security-header analysis
- Session-cookie attribute analysis
- Endpoint inventory
- Potential finding generation
- Persistent scan checks and activity logs

This module performs non-destructive GET requests only.
"""

import json
from urllib.parse import parse_qsl
import re
import time

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl
from urllib.robotparser import RobotFileParser

import httpx

from app.services.safe_transport import PinnedHTTPTransport

from sqlalchemy import select, func

from app.core.config import REQUEST_TIMEOUT, USER_AGENT
from app.models.entities import (
    Project,
    ScopeAsset,
    Endpoint,
    ScanCheck,
    Finding,
    TestCase,
)
from app.services.projects import log_activity
from app.services.workflows import validate_target, recommend_endpoint_tests


MAX_PAGES = 25
MAX_RESPONSE_BYTES = 1_000_000
MIN_DELAY_SECONDS = 0.5

# Fixed, low-volume checks. No directory brute-forcing.
EXPOSURE_PROBE_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/actuator/env",
    "/openapi.json",
    "/swagger.json",
)

DIAGNOSTIC_ORIGIN = "https://bughunter-ai.invalid"


SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "MIME sniffing protection",
    "x-frame-options": "Clickjacking protection",
    "referrer-policy": "Referrer policy",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".pdf", ".zip", ".gz",
}

SKIP_PATH_WORDS = {
    "logout", "signout", "delete", "remove",
    "unsubscribe", "checkout", "purchase",
    "payment", "destroy",
}

SESSION_COOKIE_WORDS = {
    "session", "sess", "auth", "token", "sid",
}


class LinkParser(HTMLParser):
    """Collect bounded links, forms, metadata, and inline JavaScript."""

    RESOURCE_TAGS = {
        "script", "img", "iframe", "audio", "video",
        "source", "track", "embed",
    }
    RESOURCE_LINK_RELATIONS = {"stylesheet", "preload", "modulepreload", "icon"}

    def __init__(self):
        super().__init__()
        self.links = []
        self.insecure_resources = []
        self.insecure_forms = []
        self.script_urls = []
        self.inline_scripts = []
        self.forms = []
        self.metadata = []
        self.page_text = ""
        self._current_form = None
        self._inside_script = False
        self._script_chars = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        at = {str(k).lower(): v for k, v in attrs if k}
        href, src = at.get("href"), at.get("src")

        if tag == "script":
            self._inside_script = True
            self._script_chars = 0
            if src and len(self.script_urls) < 100:
                self.script_urls.append(str(src)[:1000])

        if tag == "a" and href:
            self.links.append(href)

        if tag in self.RESOURCE_TAGS and src:
            if str(src).strip().lower().startswith("http://"):
                self.insecure_resources.append(str(src)[:500])

        if tag == "link" and href:
            rel = set(str(at.get("rel", "")).lower().split())
            if rel & self.RESOURCE_LINK_RELATIONS:
                if str(href).strip().lower().startswith("http://"):
                    self.insecure_resources.append(str(href)[:500])

        if tag == "form":
            action = str(at.get("action") or "").strip()[:1000]
            method = str(at.get("method") or "get").strip().lower()
            self._current_form = {
                "action": action,
                "method": method if method in {"get", "post", "dialog"} else "other",
                "has_password_field": False,
                "has_csrf_token": False,
                "field_names": [],
            }
            if action.lower().startswith("http://"):
                self.insecure_forms.append(action[:500])

        if tag in {"input", "select", "textarea", "button"}:
            if self._current_form is not None:
                input_type = str(at.get("type", "")).lower()
                input_name = str(at.get("name", "")).strip()[:120]

                if input_name:
                    fields = self._current_form["field_names"]
                    if input_name not in fields and len(fields) < 100:
                        fields.append(input_name)

                if tag == "input" and input_type == "password":
                    self._current_form["has_password_field"] = True

                if (
                    tag == "input"
                    and input_type == "hidden"
                    and re.search(
                        r"csrf|xsrf|authenticity|requestverificationtoken",
                        input_name,
                        re.IGNORECASE,
                    )
                ):
                    self._current_form["has_csrf_token"] = True

        if tag == "meta" and len(self.metadata) < 50:
            name = at.get("name") or at.get("property") or at.get("http-equiv")
            content = at.get("content")
            if name and content:
                self.metadata.append({
                    "name": str(name)[:120],
                    "content": str(content)[:500],
                })

        self.links = self.links[:500]
        self.insecure_resources = self.insecure_resources[:30]
        self.insecure_forms = self.insecure_forms[:30]

    def handle_data(self, data):
        if self._inside_script and self._script_chars < 250000:
            piece = data[:250000 - self._script_chars]
            if piece:
                if not self.inline_scripts or self._script_chars == 0:
                    self.inline_scripts.append(piece)
                else:
                    self.inline_scripts[-1] += piece
                self._script_chars += len(piece)
        elif not self._inside_script and len(self.page_text) < 100000:
            self.page_text += data[:100000 - len(self.page_text)]

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form" and self._current_form is not None:
            if len(self.forms) < 50:
                self.forms.append(self._current_form)
            self._current_form = None
        if tag == "script":
            self._inside_script = False
            self._script_chars = 0


def _normalize_url(url):
    parsed = urlsplit(url)

    if parsed.scheme.lower() != "https":
        return None

    if not parsed.hostname or parsed.username or parsed.password:
        return None

    # Avoid crawling parameterized URLs and fragments in this first version.
    return urlunsplit((
        "https",
        parsed.netloc.lower(),
        parsed.path or "/",
        "",
        "",
    ))


def _is_safe_page(url, origin):
    normalized = _normalize_url(url)

    if not normalized:
        return None

    parsed = urlsplit(normalized)
    base = urlsplit(origin)

    if parsed.hostname != base.hostname:
        return None

    if parsed.port not in (None, 443):
        return None

    path = parsed.path.lower()

    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return None

    path_parts = set(path.split("/"))

    if path_parts.intersection(SKIP_PATH_WORDS):
        return None

    return normalized


def _read_limited_response(client, url):
    """Read a bounded amount of decoded response content."""
    with client.stream("GET", url) as response:
        chunks = []
        total = 0
        truncated = False
        chunk_size = max(1, min(64 * 1024, MAX_RESPONSE_BYTES))

        for chunk in response.iter_bytes(chunk_size=chunk_size):
            remaining = MAX_RESPONSE_BYTES - total

            if remaining <= 0:
                truncated = bool(chunk)
                break

            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = True
                break

            chunks.append(chunk)
            total += len(chunk)

        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "cookies": response.headers.get_list("set-cookie"),
            "body": b"".join(chunks),
            "truncated": truncated,
        }


def _save_finding(
    db,
    project_id,
    title,
    category,
    severity,
    confidence,
    asset,
    description,
    evidence,
    remediation,
):
    # First preserve the existing exact-duplicate behavior.
    existing = db.scalar(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.title == title,
            Finding.asset == asset,
        ).limit(1)
    )

    if existing:
        # Never overwrite a finding that has been manually reviewed.
        if existing.status == "potential":
            severity_rank = {
                "info": 0, "low": 1, "medium": 2,
                "high": 3, "critical": 4,
            }
            confidence_rank = {
                "low": 0, "medium": 1, "high": 2,
            }

            if severity_rank.get(severity, 0) > severity_rank.get(existing.severity, 0):
                existing.severity = severity

            if confidence_rank.get(confidence, 0) > confidence_rank.get(existing.confidence, 0):
                existing.confidence = confidence

            existing.category = category
            existing.description = description
            existing.evidence = evidence
            existing.remediation = remediation

        return False

    # Correlate the same potential indicator across different assets.
    # Reviewed findings are deliberately excluded.
    correlated = db.scalar(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.title == title,
            Finding.category == category,
            Finding.status == "potential",
        ).order_by(Finding.id.asc()).limit(1)
    )

    if correlated:
        current_evidence = correlated.evidence or ""
        marker = "Additional affected assets (correlated observations):"
        asset_entry = f"- {str(asset)[:2048]}"

        if asset_entry not in current_evidence:
            if marker not in current_evidence:
                addition = f"\\n\\n{marker}\\n{asset_entry}"
            else:
                addition = f"\\n{asset_entry}"

            # Keep the evidence field bounded.
            remaining = max(0, 20000 - len(current_evidence))
            if remaining:
                correlated.evidence = (
                    current_evidence + addition[:remaining]
                )

        return False

    db.add(Finding(
        project_id=project_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        status="potential",
        asset=asset,
        description=description,
        evidence=evidence,
        remediation=remediation,
    ))

    return True

def _analyze_headers(db, project_id, url, headers):
    """Review security headers and passive technology disclosure."""
    normalized_headers = {
        str(key).lower(): str(value).strip()
        for key, value in headers.items()
    }

    missing = []

    for header, description in SECURITY_HEADERS.items():
        if header not in normalized_headers:
            missing.append(header)
            _save_finding(
                db=db,
                project_id=project_id,
                title=f"Potential missing {description}",
                category="Security Misconfiguration",
                severity="low",
                confidence="low",
                asset=url,
                description=(
                    f"The HTTPS response did not include {header}. "
                    "Impact depends on the application and deployment."
                ),
                evidence=f"Response header absent: {header}",
                remediation=(
                    f"Review whether {header} is appropriate and configure "
                    "a policy suitable for the application."
                ),
            )

    server = normalized_headers.get("server", "")
    powered_by = normalized_headers.get("x-powered-by", "")

    disclosures = []
    if server and re.search(r"\d", server):
        disclosures.append(("Server", server[:200]))
    if powered_by:
        disclosures.append(("X-Powered-By", powered_by[:200]))

    for header_name, value in disclosures:
        _save_finding(
            db=db,
            project_id=project_id,
            title=f"Technology information disclosed by {header_name}",
            category="Information Disclosure",
            severity="low",
            confidence="medium",
            asset=url,
            description=(
                "The response exposes server or platform information that "
                "may help identify the technology stack. This does not by "
                "itself establish a vulnerability."
            ),
            evidence=f"{header_name}: {value}",
            remediation=(
                "Consider removing unnecessary technology details from "
                "public response headers."
            ),
        )

    referrer = normalized_headers.get("referrer-policy", "").lower()
    unsafe_referrer_values = {
        "unsafe-url",
        "no-referrer-when-downgrade",
    }

    if referrer in unsafe_referrer_values:
        _save_finding(
            db=db,
            project_id=project_id,
            title="Potentially weak Referrer-Policy",
            category="Security Misconfiguration",
            severity="low",
            confidence="medium",
            asset=url,
            description=(
                "The response uses a Referrer-Policy that may disclose "
                "full URL paths or query information to other origins."
            ),
            evidence=f"Observed Referrer-Policy: {referrer}",
            remediation=(
                "Consider strict-origin-when-cross-origin, strict-origin, "
                "same-origin, or no-referrer according to application needs."
            ),
        )

    content_options = normalized_headers.get("x-content-type-options", "")
    if content_options and content_options.lower() != "nosniff":
        _save_finding(
            db=db,
            project_id=project_id,
            title="Potentially ineffective MIME-sniffing protection",
            category="Security Misconfiguration",
            severity="low",
            confidence="medium",
            asset=url,
            description=(
                "X-Content-Type-Options is present but does not use the "
                "expected nosniff value."
            ),
            evidence=f"Observed X-Content-Type-Options: {content_options[:200]}",
            remediation="Configure X-Content-Type-Options: nosniff where appropriate.",
        )

    return missing

def _analyze_cookies(db, project_id, url, cookie_headers):
    for cookie_header in cookie_headers:
        parts = [part.strip() for part in cookie_header.split(";")]

        if not parts or "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()
        name_lower = cookie_name.lower()

        if not any(word in name_lower for word in SESSION_COOKIE_WORDS):
            continue

        flags = {
            part.split("=", 1)[0].strip().lower()
            for part in parts[1:]
            if part
        }

        for flag, description in (
            ("secure", "Secure"),
            ("httponly", "HttpOnly"),
            ("samesite", "SameSite"),
        ):
            if flag in flags:
                continue

            _save_finding(
                db=db,
                project_id=project_id,
                title=f"Potential session cookie missing {description}",
                category="Session Management",
                severity="low",
                confidence="low",
                asset=url,
                description=(
                    f"The cookie named '{cookie_name}' appears session-related "
                    f"but does not include the {description} attribute. "
                    "Cookie purpose and application context require review."
                ),
                evidence=f"Set-Cookie attribute absent: {description}",
                remediation=(
                    "Review the cookie's purpose and configure Secure, "
                    "HttpOnly, and an appropriate SameSite policy."
                ),
            )





def _analyze_policy_headers(db, project_id, url, headers):
    normalized = {
        key.lower(): value.strip()
        for key, value in headers.items()
    }

    results = {}

    # Content Security Policy review.
    csp = normalized.get("content-security-policy", "")
    if csp:
        directives = {}

        for item in csp.split(";"):
            parts = item.strip().split()
            if parts:
                directives[parts[0].lower()] = [
                    value.lower() for value in parts[1:]
                ]

        weak_reasons = []

        # Duplicate directives can cause unexpected browser policy handling.
        directive_names = re.findall(
            r"(?:^|;)\\s*([a-zA-Z][a-zA-Z0-9-]*)\\s+",
            csp,
        )
        duplicates = sorted({
            name.lower() for name in directive_names
            if directive_names.count(name) > 1
        })
        if duplicates:
            weak_reasons.append(
                "duplicate CSP directives: " + ", ".join(duplicates)
            )

        script_sources = directives.get("script-src", [])
        default_sources = directives.get("default-src", [])

        if "'unsafe-inline'" in script_sources:
            weak_reasons.append("script-src permits unsafe-inline")

        if "'unsafe-eval'" in script_sources:
            weak_reasons.append("script-src permits unsafe-eval")

        effective_script_sources = script_sources or default_sources

        if "*" in effective_script_sources:
            weak_reasons.append("effective script sources permit wildcard access")

        if "http:" in effective_script_sources:
            weak_reasons.append("effective script sources permit insecure HTTP")

        if "data:" in effective_script_sources:
            weak_reasons.append("effective script sources permit data URLs")

        for directive in ("object-src", "base-uri", "frame-ancestors"):
            if directive not in directives:
                weak_reasons.append(
                    f"the {directive} directive is not explicitly configured"
                )

        connect_sources = directives.get(
            "connect-src", default_sources
        )
        if "*" in connect_sources:
            weak_reasons.append("connect-src permits wildcard destinations")
        if "http:" in connect_sources:
            weak_reasons.append("connect-src permits insecure HTTP destinations")

        frame_sources = directives.get("frame-ancestors", [])
        if "*" in frame_sources:
            weak_reasons.append("frame-ancestors permits all framing origins")

        results["csp"] = {
            "present": True,
            "directives": list(directives.keys()),
            "review_notes": weak_reasons,
        }

        if weak_reasons:
            _save_finding(
                db=db,
                project_id=project_id,
                title="Potential weak Content Security Policy",
                category="Security Misconfiguration",
                severity="low",
                confidence="medium",
                asset=url,
                description=(
                    "The Content Security Policy contains potentially weak "
                    "directives or lacks important restrictions. Actual "
                    "impact depends on the application's content and policy."
                ),
                evidence="; ".join(weak_reasons)[:1500],
                remediation=(
                    "Review the CSP against the application's requirements. "
                    "Restrict script sources, avoid unsafe-inline and "
                    "unsafe-eval where possible, and consider object-src "
                    "'none', an appropriate base-uri, and frame-ancestors."
                ),
            )
    else:
        results["csp"] = {"present": False}

    # HSTS review. Missing HSTS is already handled by _analyze_headers.
    hsts = normalized.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)

        if not match:
            reason = "HSTS max-age is missing or invalid"
            max_age = None
        else:
            max_age = int(match.group(1))
            reason = (
                "HSTS max-age is shorter than the recommended "
                "six-month review threshold"
                if max_age < 15552000 else ""
            )

        results["hsts"] = {
            "present": True,
            "max_age_seconds": max_age,
            "review_note": reason or "max-age meets the six-month threshold",
        }

        if reason:
            _save_finding(
                db=db,
                project_id=project_id,
                title="Potential weak HSTS policy",
                category="Security Misconfiguration",
                severity="low",
                confidence="medium",
                asset=url,
                description=(
                    "The HSTS response header has a missing, invalid, "
                    "or short max-age value."
                ),
                evidence=f"{reason}. Observed header: {hsts[:500]}",
                remediation=(
                    "Review the deployment's HSTS policy and use an "
                    "appropriate max-age, commonly at least 15552000 "
                    "seconds, after confirming HTTPS readiness."
                ),
            )
    else:
        results["hsts"] = {"present": False}

    _save_check(
        db,
        project_id,
        url,
        "CSP and HSTS policy review",
        "completed",
        json.dumps(results),
    )


def _analyze_html_security(db, project_id, url, parser):
    page = urlsplit(url)
    page_origin = (page.scheme.lower(), (page.hostname or "").lower(), page.port or 443)
    external_forms, password_get_forms = [], []

    for form in parser.forms[:50]:
        action = form.get("action", "")
        target = urlsplit(urljoin(url, action) if action else url)
        target_origin = (
            target.scheme.lower(), (target.hostname or "").lower(),
            target.port or (443 if target.scheme.lower() == "https" else 80),
        )
        item = {
            "method": form.get("method", "get"),
            "action": urljoin(url, action) if action else url,
            "has_password_field": bool(form.get("has_password_field")),
            "has_csrf_token": bool(form.get("has_csrf_token")),
        }
        if target_origin != page_origin:
            external_forms.append(item)
        if item["has_password_field"] and item["method"] == "get":
            password_get_forms.append(item)

    sensitive_meta = [
        m for m in parser.metadata
        if re.search(
            r"\b(password|passwd|secret|api[_-]?key|access[_-]?token|private|internal|staging|debug)\b",
            m["name"] + " " + m["content"], re.I
        )
    ]

    searchable = (parser.page_text + "\n" + "\n".join(parser.inline_scripts))[:350000]

    sql_error_patterns = (
        r"SQLSTATE\[[0-9A-Z]+\]",
        r"You have an error in your SQL syntax",
        r"SQL syntax.*(?:error|near)",
        r"Unclosed quotation mark after the character string",
        r"PDOException",
        r"mysql_fetch_(?:array|assoc|row)",
        r"SQLite(?:3)?::",
        r"PostgreSQL.*\bERROR\b",
    )
    sql_error_matches = []
    for pattern in sql_error_patterns:
        match = re.search(pattern, searchable, re.I)
        if match:
            sql_error_matches.append(match.group(0)[:120])

    csrf_meta_present = any(
        re.search(r"csrf|xsrf", m.get("name", ""), re.I)
        for m in parser.metadata
    )
    csrf_missing_forms = [
        f for f in parser.forms
        if f.get("method") == "post"
        and not f.get("has_csrf_token")
        and not csrf_meta_present
    ]

    patterns = (
        r"\bdebug\s*[:=]\s*(?:true|1)",
        r"\b(?:development|dev-build|staging)\b",
        r"webpackHotUpdate|__VUE_PROD_DEVTOOLS__|react\.development",
        r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?",
    )
    debug_matches = []
    for pattern in patterns:
        match = re.search(pattern, searchable, re.I)
        if match:
            debug_matches.append(match.group(0)[:160])

    details = {
        "insecure_resource_count": len(parser.insecure_resources),
        "insecure_resource_samples": parser.insecure_resources[:10],
        "insecure_form_count": len(parser.insecure_forms),
        "insecure_form_samples": parser.insecure_forms[:10],
        "forms_reviewed": len(parser.forms),
        "password_get_form_count": len(password_get_forms),
        "csrf_candidate_forms": len(csrf_missing_forms),
        "sql_error_indicator_count": len(sql_error_matches),
        "sql_error_indicator_samples": sql_error_matches[:5],
        "external_form_count": len(external_forms),
        "external_form_samples": external_forms[:5],
        "sensitive_metadata_count": len(sensitive_meta),
        "sensitive_metadata_samples": sensitive_meta[:5],
        "development_indicator_samples": debug_matches[:8],
        "external_resources_requested": False,
        "forms_submitted": False,
    }

    findings = []

    if parser.insecure_resources:
        findings.append((
            "Potential mixed-content resources", "Transport Security", "low", "medium",
            "The HTTPS page references resources using HTTP.",
            parser.insecure_resources[:10],
            "Serve all page resources over HTTPS.",
        ))

    if parser.insecure_forms:
        findings.append((
            "Potential insecure HTTP form submission", "Transport Security", "medium", "medium",
            "A form explicitly targets HTTP, which could expose submitted data in transit.",
            parser.insecure_forms[:10],
            "Change form actions to HTTPS and enforce secure transport.",
        ))

    if password_get_forms:
        findings.append((
            "Potential password form using GET method", "Sensitive Data Exposure", "medium", "medium",
            "A password field appears in a GET form. Submitted credentials may appear in URLs, browser history, or logs.",
            password_get_forms[:5],
            "Use POST for password forms and never place credentials in URLs.",
        ))

    external_passwords = [f for f in external_forms if f["has_password_field"]]
    if external_passwords:
        findings.append((
            "Password form targets an external origin", "Sensitive Data Exposure", "medium", "medium",
            "A password form targets another origin. This may be legitimate identity-provider integration and needs owner verification.",
            external_passwords[:5],
            "Verify the destination is an approved identity provider and uses HTTPS.",
        ))
    elif external_forms:
        findings.append((
            "Form submits to an external origin", "Security Review", "low", "low",
            "A form targets another origin. Review the destination and data-sharing purpose.",
            external_forms[:5],
            "Confirm external form destinations are trusted and receive only necessary data.",
        ))

    if csrf_missing_forms:
        findings.append((
            "Potential missing CSRF protection on POST form",
            "CSRF",
            "medium",
            "low",
            "A POST form has no recognised hidden CSRF token, and no CSRF meta token was detected. Framework-level or SameSite protections may still exist.",
            [
                {"action": f.get("action", ""), "method": f.get("method", "post")}
                for f in csrf_missing_forms[:5]
            ],
            "Verify server-side CSRF token validation, Origin/Referer checks, and appropriate SameSite cookie settings.",
        ))

    if sql_error_matches:
        findings.append((
            "Potential database error disclosure (review for SQL injection)",
            "Information Disclosure",
            "medium",
            "low",
            "Database-related error signatures appear in the public response. This may expose implementation details but does not prove SQL injection.",
            sql_error_matches[:5],
            "Return generic client errors, log database details server-side, and verify parameterised queries in the application code.",
        ))

    if sensitive_meta:
        findings.append((
            "Potential sensitive information in HTML metadata", "Information Disclosure", "low", "low",
            "Metadata contains terms associated with secrets or internal environments; the values may be harmless and need review.",
            sensitive_meta[:5],
            "Remove internal-only details and secret-like values from public metadata.",
        ))

    if debug_matches:
        findings.append((
            "Potential development or debug indicators in page content", "Information Disclosure", "low", "low",
            "Development/debug markers appear in page content. This does not prove debug mode is enabled.",
            debug_matches[:8],
            "Review production assets and remove unnecessary development diagnostics.",
        ))

    for title, category, severity, confidence, description, evidence, remediation in findings:
        _save_finding(
            db=db, project_id=project_id, title=title, category=category,
            severity=severity, confidence=confidence, asset=url,
            description=description, evidence=json.dumps(evidence)[:2000],
            remediation=remediation,
        )

    _save_check(
        db, project_id, url,
        "HTML transport, form, metadata, and debug review",
        "completed", json.dumps(details)[:12000],
    )

    return {
        "forms_reviewed": len(parser.forms),
        "password_get_forms": len(password_get_forms),
        "csrf_candidate_forms": len(csrf_missing_forms),
        "sql_error_indicators": len(sql_error_matches),
        "external_forms": len(external_forms),
        "sensitive_metadata": len(sensitive_meta),
        "development_indicators": len(debug_matches),
        "mixed_content_pages": int(bool(parser.insecure_resources)),
        "insecure_form_pages": int(bool(parser.insecure_forms)),
    }


def _analyze_cors(db, project_id, url, headers):
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    allowed_origin = normalized.get("access-control-allow-origin", "")
    credentials = normalized.get(
        "access-control-allow-credentials", ""
    ).lower() == "true"

    details = {
        "allow_origin": allowed_origin or "not present",
        "allow_credentials": credentials,
        "diagnostic_origin": DIAGNOSTIC_ORIGIN,
    }

    if allowed_origin == DIAGNOSTIC_ORIGIN and credentials:
        _save_finding(
            db=db,
            project_id=project_id,
            title="Potential permissive credentialed CORS policy",
            category="Security Misconfiguration",
            severity="medium",
            confidence="medium",
            asset=url,
            description=(
                "The response allowed the diagnostic origin and credentials. "
                "Review whether untrusted websites can read sensitive "
                "authenticated responses."
            ),
            evidence=(
                "Access-Control-Allow-Origin matched the diagnostic origin; "
                "Access-Control-Allow-Credentials: true. "
                "No authenticated data was accessed."
            ),
            remediation=(
                "Use an explicit allowlist of trusted origins. "
                "Do not reflect arbitrary Origin values when credentials "
                "are enabled."
            ),
        )

    _save_check(
        db, project_id, url, "CORS response policy",
        "completed", json.dumps(details)
    )




def _extract_js_api_candidates(content, limit=300):
    """
    Extract likely API operations from downloaded JavaScript text.

    Static analysis only: JavaScript is never executed and extracted
    URLs are never contacted by this function.
    """
    if not isinstance(content, str):
        return []

    content = content[:1_000_000]
    results = []
    seen = set()

    def add(path, method, origin):
        if not isinstance(path, str):
            return

        path = path.strip()
        if not path or len(path) > 1000:
            return

        if not path.startswith(("/", "https://")):
            return

        method = str(method or "GET").upper()
        allowed = {
            "GET", "POST", "PUT", "PATCH",
            "DELETE", "OPTIONS", "HEAD",
        }
        if method not in allowed:
            method = "GET"

        try:
            parsed = urlsplit(path)
        except ValueError:
            return

        if parsed.scheme and parsed.scheme != "https":
            return
        if parsed.username is not None or parsed.password is not None:
            return

        if re.search(
            r"\.(?:js|mjs|css|map|png|jpg|jpeg|svg|ico|woff2?|ttf)$",
            parsed.path,
            re.IGNORECASE,
        ):
            return

        key = (path, method)
        if key in seen:
            return

        seen.add(key)
        results.append({
            "path": path,
            "method": method,
            "source": origin,
        })

    call_pattern = re.compile(
        r"\b(fetch|axios\.(?:get|post|put|patch|delete|options|head))"
        r"\s*\(\s*(['\"`])([^'\"`\r\n]{1,1000})\2",
        re.IGNORECASE,
    )

    for match in call_pattern.finditer(content):
        function = match.group(1).lower()
        method = (
            function.split(".", 1)[1].upper()
            if "." in function else "GET"
        )

        if function == "fetch":
            context = content[match.end():match.end() + 700]
            method_match = re.search(
                r"\bmethod\s*:\s*(['\"])(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\1",
                context,
                re.IGNORECASE,
            )
            if method_match:
                method = method_match.group(2).upper()

        add(match.group(3), method, "JavaScript HTTP client call")
        if len(results) >= limit:
            return results

    xhr_pattern = re.compile(
        r"\.open\s*\(\s*(['\"])(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\1"
        r"\s*,\s*(['\"])([^'\"\r\n]{1,1000})\3",
        re.IGNORECASE,
    )

    for match in xhr_pattern.finditer(content):
        add(match.group(4), match.group(2), "XMLHttpRequest.open")
        if len(results) >= limit:
            return results

    route_pattern = re.compile(
        r"""(['"`])(/(?:api|graphql|auth|oauth|rest|v[0-9]+|trpc|rpc|webhooks|services|backend)(?:/[A-Za-z0-9_./{}:$-]*)?(?:\?[A-Za-z0-9_.,=&%{}:$-]*)?)\1""",
        re.IGNORECASE,
    )

    for match in route_pattern.finditer(content):
        route_path = match.group(2)

        # Do not invent a GET operation when a call already supplied
        # an explicit HTTP method for this same route.
        if any(item["path"] == route_path for item in results):
            continue

        add(route_path, "GET", "JavaScript API route literal")
        if len(results) >= limit:
            break

    return results[:limit]

def _discover_client_routes(db, project_id, page_url, origin, parser, html):
    """Passively inventory same-host assets, API routes and parameter names."""
    candidates = []
    seen = set()
    discovered = 0
    parameter_names = set()
    form_field_names = set()
    form_summaries = []

    def collect_parameter_names(raw_url):
        if not isinstance(raw_url, str) or len(raw_url) > 3000:
            return

        try:
            absolute = urljoin(page_url, raw_url)
            parsed_url = urlsplit(absolute)

            if (
                parsed_url.scheme != "https"
                or parsed_url.hostname != urlsplit(origin).hostname
                or parsed_url.port not in (None, 443)
            ):
                return

            for name, _value in parse_qsl(
                parsed_url.query[:2000],
                keep_blank_values=True,
                max_num_fields=100,
            ):
                name = name.strip()[:120]
                if name and len(parameter_names) < 100:
                    parameter_names.add(name)
        except (ValueError, TypeError):
            return

    for item in parser.script_urls[:100]:
        candidates.append({
            "path": item,
            "method": "GET",
            "type": "Client-side JavaScript asset",
            "source": "HTML script reference",
        })

    for link in parser.links[:500]:
        collect_parameter_names(str(link))

    for form in parser.forms[:50]:
        action = str(form.get("action", "")).strip()
        if action:
            collect_parameter_names(action)
            candidates.append({
                "path": action,
                "method": (
                    str(form.get("method", "get")).upper()
                    if form.get("method") in {"get", "post"}
                    else "GET"
                ),
                "type": "HTML form action",
                "source": "HTML form",
            })

        for field_name in form.get("field_names", [])[:100]:
            if isinstance(field_name, str) and field_name.strip():
                form_field_names.add(field_name.strip()[:120])

        if len(form_summaries) < 50:
            form_summaries.append({
                "method": str(form.get("method", "other"))[:12],
                "field_names": [
                    str(name)[:120]
                    for name in form.get("field_names", [])[:100]
                    if isinstance(name, str)
                ],
            })

    source = (
        "\n".join(parser.inline_scripts[:100])
        + "\n"
        + html[:500000]
    )

    api_candidates = _extract_js_api_candidates(source)
    for item in api_candidates:
        candidates.append({
            "path": item["path"],
            "method": item["method"],
            "type": "Client-side API route",
            "source": item["source"],
        })
        collect_parameter_names(item["path"])

    base = urlsplit(origin)

    for item in candidates[:300]:
        raw_url = item["path"]
        method = item["method"]
        endpoint_type = item["type"]

        try:
            normalized = _normalize_url(urljoin(page_url, raw_url))
        except (ValueError, TypeError):
            continue

        if not normalized or normalized in seen:
            continue

        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or parsed.hostname != base.hostname
            or parsed.port not in (None, 443)
        ):
            continue

        if any(
            word in parsed.path.lower().split("/")
            for word in SKIP_PATH_WORDS
        ):
            continue

        seen.add(normalized)

        try:
            if _save_endpoint(
                db,
                project_id,
                normalized,
                endpoint_type,
                method=method,
                notes=(
                    f"Discovered from {item['source']} on {page_url}. "
                    "Static discovery only; operation was not executed."
                ),
            ):
                discovered += 1
        except ValueError:
            continue

    if parameter_names or form_field_names or form_summaries:
        _save_check(
            db,
            project_id,
            page_url,
            "Passive endpoint parameter inventory",
            "completed",
            json.dumps({
                "query_parameter_names": sorted(parameter_names),
                "form_field_names": sorted(form_field_names)[:100],
                "forms": form_summaries,
                "values_collected": False,
                "forms_submitted": False,
            }),
        )

    if api_candidates:
        _save_check(
            db,
            project_id,
            page_url,
            "JavaScript API operation discovery",
            "completed",
            json.dumps({
                "operations_detected": len(api_candidates),
                "methods": sorted({
                    item["method"] for item in api_candidates
                }),
                "source_types": sorted({
                    item["source"] for item in api_candidates
                }),
                "javascript_executed": False,
                "requests_to_discovered_routes": 0,
            }),
        )

    return discovered

def _discover_source_maps(db, project_id, js_url, origin, content):
    """Record same-origin source-map references without downloading them."""
    pattern = re.compile(
        r"(?:\/\/[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)"
        r"([^\s*]+)",
        re.IGNORECASE,
    )
    origin_host = urlsplit(origin).hostname
    discovered = 0
    seen = set()

    for match in pattern.finditer(content[:1_000_000]):
        candidate = urljoin(js_url, match.group(1).strip())
        parsed = urlsplit(candidate)

        try:
            safe = (
                parsed.scheme == "https"
                and parsed.hostname == origin_host
                and parsed.port in (None, 443)
                and parsed.username is None
                and parsed.password is None
                and bool(parsed.path)
            )
        except ValueError:
            safe = False

        if not safe or candidate in seen:
            continue

        if any(
            word in parsed.path.lower().split("/")
            for word in SKIP_PATH_WORDS
        ):
            continue

        seen.add(candidate)

        try:
            validate_target(db, project_id, candidate)
        except ValueError:
            continue

        if _save_endpoint(
            db, project_id, candidate, "JavaScript source map reference"
        ):
            discovered += 1

    if seen:
        _save_check(
            db, project_id, js_url,
            "JavaScript source-map reference review",
            "completed",
            json.dumps({
                "references_found": len(seen),
                "new_endpoints_recorded": discovered,
                "source_maps_downloaded": False,
            }),
        )

    return discovered


def _analyze_client_content(db, project_id, url, content):
    """Identify possible exposed secrets without retaining matched values."""
    patterns = (
        (
            "Private key material marker",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "high",
            "medium",
        ),
        (
            "AWS access key identifier pattern",
            r"\bAKIA[0-9A-Z]{16}\b",
            "medium",
            "low",
        ),
        (
            "GitHub token format marker",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            "medium",
            "low",
        ),
        (
            "Slack token format marker",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            "medium",
            "low",
        ),
    )

    detected = []

    for label, regex, severity, confidence in patterns:
        if not re.search(regex, content):
            continue

        detected.append(label)

        _save_finding(
            db=db,
            project_id=project_id,
            title=f"Potential exposed secret: {label}",
            category="Sensitive Data Exposure",
            severity=severity,
            confidence=confidence,
            asset=url,
            description=(
                "Downloaded public content contains a recognizable "
                "secret-related marker. Credential validity and exposure "
                "impact have not been verified."
            ),
            evidence=(
                f"Detected marker: {label}. Matched values were not stored."
            ),
            remediation=(
                "Review the source through authorized access. Remove "
                "unintended secrets, rotate affected credentials where "
                "appropriate, and inspect relevant access logs."
            ),
        )

    if detected:
        _save_check(
            db, project_id, url,
            "Client-side sensitive marker review", "completed",
            json.dumps({
                "markers": detected,
                "secret_values_saved": False,
            }),
        )

    return len(detected)


def _analyze_client_security_patterns(db, project_id, url, content):
    """Flag risky JavaScript constructs for manual review; never execute code."""
    checks = (
        (
            "Potential unsafe DOM HTML sink",
            r"\.(?:innerHTML|outerHTML)\s*(?:\+?=)|"
            r"\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(",
            "medium",
            "Client code uses an HTML-writing DOM operation. Review whether "
            "untrusted data can reach it without safe sanitization.",
        ),
        (
            "Potential dynamic code execution",
            r"\beval\s*\(|\bnew\s+Function\s*\(",
            "medium",
            "Client code contains a dynamic code-execution construct. Review "
            "whether externally controlled data can influence execution.",
        ),
        (
            "Wildcard postMessage target",
            r"\.postMessage\s*\([^;]{0,500},\s*['\"]\*['\"]\s*\)",
            "low",
            "Client code appears to send a postMessage using a wildcard target "
            "origin. Review message confidentiality and origin restrictions.",
        ),
        (
            "Potential framework unsafe HTML rendering",
            r"\bdangerouslySetInnerHTML\s*=",
            "medium",
            "Client code uses a framework API that inserts raw HTML. Verify "
            "that the HTML is trusted or safely sanitized.",
        ),
        (
            "Direct document cookie access",
            r"\bdocument\s*\.\s*cookie\b",
            "low",
            "Client code accesses document.cookie. Review cookie contents and "
            "ensure sensitive session cookies are protected with HttpOnly.",
        ),
        (
            "Potential sensitive browser storage",
            r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*"
            r"['\"][^'\"]*(?:token|auth|password|secret|session)[^'\"]*['\"]",
            "medium",
            "Client code appears to store authentication or secret-related "
            "data in browser storage. Review whether this exposes credentials "
            "to JavaScript running in the page.",
        ),
        (
            "Potential weak randomness in security context",
            r"Math\.random\s*\([^)]*\)[\s\S]{0,200}"
            r"(?:token|nonce|session|csrf|secret)",
            "low",
            "Math.random appears near a security-sensitive identifier. "
            "Confirm that cryptographically secure randomness is used where "
            "required.",
        ),
    )

    detected = []
    for title, regex, severity, description in checks:
        if not re.search(regex, content, re.IGNORECASE):
            continue

        detected.append(title)
        _save_finding(
            db=db,
            project_id=project_id,
            title=title,
            category="Client-Side Security",
            severity=severity,
            confidence="low",
            asset=url,
            description=description,
            evidence=(
                "A potentially risky JavaScript pattern was found in "
                "downloaded client-side content. Exploitability was not tested."
            ),
            remediation=(
                "Review the relevant code path, validate and encode untrusted "
                "data, use safe DOM APIs, protect session credentials, and "
                "use cryptographically secure randomness where appropriate."
            ),
        )

    if detected:
        _save_check(
            db, project_id, url,
            "Static JavaScript security pattern review",
            "completed",
            json.dumps({
                "potential_patterns": detected,
                "code_executed": False,
            }),
        )

    return len(detected)



def _canonical_endpoint_url(url):
    """Normalize URL presentation without merging distinct paths or queries."""
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Invalid endpoint URL.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Endpoint URL credentials are not permitted.")

    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port

    if ":" in host:
        host = f"[{host}]"

    default_port = 443 if scheme == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"

    return urlunsplit((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))




def _openapi_operation_metadata(document, path_item, operation, documented_path):
    """Extract bounded OpenAPI names and declarations only; never values."""
    def compact(value):
        return re.sub(r"[^a-z0-9]", "", str(value).lower())

    identity_markers = {
        "userid", "accountid", "customerid", "ownerid", "tenantid",
        "roleid", "organizationid", "orgid", "projectid", "orderid",
        "invoiceid", "profileid", "resourceid", "memberid",
    }
    sensitive_markers = {
        "token", "secret", "password", "passwd", "credential",
        "authorization", "apikey", "privatekey", "session",
        "cookie", "accesskey", "refreshkey",
    }

    parameters_by_key = {}
    for collection in (
        path_item.get("parameters", []),
        operation.get("parameters", []),
    ):
        if not isinstance(collection, list):
            continue
        for item in collection[:100]:
            if not isinstance(item, dict):
                continue
            name, location = item.get("name"), item.get("in")
            if (
                isinstance(name, str)
                and isinstance(location, str)
                and location in {"path", "query", "header", "cookie"}
            ):
                parameters_by_key[(name[:120], location)] = {
                    "name": name[:120], "in": location
                }

    for name in re.findall(r"\{([^{}]{1,120})\}", documented_path):
        parameters_by_key.setdefault(
            (name, "path"), {"name": name, "in": "path"}
        )

    parameters = list(parameters_by_key.values())[:200]
    identity_names = sorted({
        x["name"] for x in parameters
        if compact(x["name"]) in identity_markers
    })
    sensitive_names = sorted({
        x["name"] for x in parameters
        if any(marker in compact(x["name"]) for marker in sensitive_markers)
    })

    def resolve_ref(reference):
        if not isinstance(reference, str) or not reference.startswith("#/"):
            return None
        current = document
        try:
            for part in reference[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                current = current[part]
            return current if isinstance(current, dict) else None
        except (KeyError, TypeError):
            return None

    body_fields = set()
    visited = set()

    def collect_schema(schema, depth=0):
        if depth > 5 or not isinstance(schema, dict):
            return
        reference = schema.get("$ref")
        if isinstance(reference, str) and reference not in visited:
            visited.add(reference)
            resolved = resolve_ref(reference)
            if resolved:
                collect_schema(resolved, depth + 1)

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for name, child in list(properties.items())[:100]:
                if isinstance(name, str):
                    body_fields.add(name[:120])
                if isinstance(child, dict):
                    collect_schema(child, depth + 1)

        for key in ("allOf", "oneOf", "anyOf"):
            children = schema.get(key, [])
            if isinstance(children, list):
                for child in children[:20]:
                    collect_schema(child, depth + 1)

        if isinstance(schema.get("items"), dict):
            collect_schema(schema["items"], depth + 1)

    request_body = operation.get("requestBody", {})
    if isinstance(request_body, dict):
        if isinstance(request_body.get("$ref"), str):
            request_body = resolve_ref(request_body["$ref"]) or {}
        content = request_body.get("content", {})
        if isinstance(content, dict):
            for media in list(content.values())[:20]:
                if isinstance(media, dict):
                    collect_schema(media.get("schema"))

    # Swagger 2 body and form fields.
    all_parameters = (
        path_item.get("parameters", [])
        if isinstance(path_item.get("parameters", []), list) else []
    ) + (
        operation.get("parameters", [])
        if isinstance(operation.get("parameters", []), list) else []
    )
    for item in all_parameters[:200]:
        if not isinstance(item, dict):
            continue
        if item.get("in") == "body":
            collect_schema(item.get("schema"))
        elif item.get("in") == "formData" and isinstance(item.get("name"), str):
            body_fields.add(item["name"][:120])

    body_fields = sorted(body_fields)[:200]

    components = document.get("components", {})
    schemes = (
        components.get("securitySchemes", {})
        if isinstance(components, dict) else {}
    )
    if not schemes:
        schemes = document.get("securityDefinitions", {})
    if not isinstance(schemes, dict):
        schemes = {}

    security = (
        operation.get("security")
        if "security" in operation else document.get("security", [])
    )
    security_names = set()
    if isinstance(security, list):
        for requirement in security[:50]:
            if isinstance(requirement, dict):
                security_names.update(
                    str(name)[:120] for name in requirement
                )

    return {
        "parameters": parameters,
        "parameter_locations": sorted({x["in"] for x in parameters}),
        "identity_parameter_names": identity_names,
        "sensitive_parameter_names": sensitive_names,
        "request_body_field_names": body_fields,
        "request_body_required": bool(
            request_body.get("required", False)
            if isinstance(request_body, dict) else False
        ),
        "security_declared": bool(security),
        "security_explicitly_empty": (
            "security" in operation and operation.get("security") == []
        ),
        "security_requirement_names": sorted(security_names),
        "available_security_scheme_names": sorted(
            str(name)[:120] for name in schemes
        )[:100],
    }


def _save_endpoint(
    db,
    project_id,
    url,
    endpoint_type="Discovered web page",
    method="GET",
    notes="",
):
    # Every discovered endpoint must pass the existing scope validator.
    validate_target(db, project_id, url)

    canonical = _canonical_endpoint_url(url)
    method = str(method or "GET").upper().strip()

    allowed_methods = {
        "GET", "POST", "PUT", "PATCH", "DELETE",
        "OPTIONS", "HEAD",
    }
    if method not in allowed_methods:
        method = "GET"

    existing_endpoints = db.scalars(
        select(Endpoint).where(Endpoint.project_id == project_id)
    ).all()

    for endpoint in existing_endpoints:
        try:
            if (
                _canonical_endpoint_url(endpoint.url) == canonical
                and (endpoint.method or "GET").upper() == method
            ):
                incoming_notes = str(notes or "").strip()
                existing_notes = str(endpoint.notes or "")

                if incoming_notes and incoming_notes not in existing_notes:
                    endpoint.notes = (
                        existing_notes + "\\n" + incoming_notes
                    ).strip()[-4000:]

                if endpoint_type == "OpenAPI documented API operation":
                    endpoint.endpoint_type = endpoint_type

                recommend_endpoint_tests(db, project_id, endpoint.id)
                return False
        except (ValueError, TypeError):
            continue

    endpoint = Endpoint(
        project_id=project_id,
        url=canonical,
        endpoint_type=str(endpoint_type)[:80],
        method=method,
        notes=(
            str(notes or "Automatically discovered by BugHunter AI.")
            [:4000]
        ),
    )
    db.add(endpoint)
    db.flush()

    # Recommendations are manual tasks only. No active tests are run here.
    recommend_endpoint_tests(db, project_id, endpoint.id)
    return True

def _save_check(db, project_id, url, check_name, outcome, details):
    db.add(ScanCheck(
        project_id=project_id,
        asset=url,
        check_name=check_name,
        outcome=outcome,
        details=details[:8000],
    ))



def _record_openapi_operation_assessment(
    db, project_id, url, method, documented_path, operation_id, metadata
):
    """
    Record bounded OpenAPI operation intelligence.

    This is documentation analysis only. It never calls the operation.
    """
    metadata = metadata if isinstance(metadata, dict) else {}
    method = str(method or "GET").upper()[:12]

    def safe_names(value, limit=30):
        if not isinstance(value, (list, tuple, set)):
            return []
        return sorted({
            str(item)[:120]
            for item in value
            if isinstance(item, (str, int))
        })[:limit]

    security_declared = metadata.get("security_declared") is True
    explicitly_empty = (
        metadata.get("security_explicitly_empty") is True
    )
    identity_names = safe_names(
        metadata.get("identity_parameter_names")
    )
    sensitive_parameters = safe_names(
        metadata.get("sensitive_parameter_names")
    )
    body_fields = safe_names(
        metadata.get("request_body_field_names"), 50
    )
    security_schemes = safe_names(
        metadata.get("security_requirement_names")
    )
    available_schemes = safe_names(
        metadata.get("available_security_scheme_names")
    )

    if explicitly_empty:
        security_status = "operation explicitly declares an empty security requirement"
    elif not security_declared:
        security_status = "no inherited or operation security requirement declared"
    else:
        security_status = "security requirement declared"

    write_method = method in {"POST", "PUT", "PATCH", "DELETE"}

    indicators = []
    if explicitly_empty:
        indicators.append("explicit_empty_security_requirement")
    elif not security_declared:
        indicators.append("security_requirement_not_documented")

    if identity_names:
        indicators.append("identity_related_parameters")
    if sensitive_parameters:
        indicators.append("sensitive_parameter_names")
    if write_method:
        indicators.append("write_operation_requires_controlled_review")

    result = {
        "assessment": "OpenAPI documented operation review",
        "documented_path": str(documented_path or "")[:500],
        "operation_id": str(operation_id or "")[:120],
        "method": method,
        "security_status": security_status,
        "security_declared": security_declared,
        "security_explicitly_empty": explicitly_empty,
        "security_requirement_names": security_schemes,
        "available_security_scheme_names": available_schemes,
        "identity_parameter_names": identity_names,
        "sensitive_parameter_names": sensitive_parameters,
        "request_body_field_names": body_fields,
        "request_body_required": (
            metadata.get("request_body_required") is True
        ),
        "write_operation": write_method,
        "indicators": indicators,
        "manual_review_required": True,
        "auto_confirmed": False,
        "network_requests_made": 0,
        "payloads_executed": False,
        "interpretation": (
            "OpenAPI declarations describe intended API behavior. "
            "They do not prove live authentication enforcement, "
            "authorization, or exposure of sensitive data."
        ),
    }

    _save_check(
        db,
        project_id,
        url,
        "OpenAPI documented operation assessment",
        "completed",
        json.dumps(result, ensure_ascii=True)[:8000],
    )


def _analyze_reflected_query_inputs(
    db, project_id, url, content_type, body, truncated=False
):
    """
    Passively identify existing query values reflected in the fetched response.

    This is an observation only, not an XSS test. No payloads or requests
    are generated, and query values are never persisted.
    """
    parsed = urlsplit(url)
    safe_asset = parsed._replace(query="", fragment="").geturl()

    try:
        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=False,
            max_num_fields=100,
        )
    except (ValueError, TypeError):
        _save_check(
            db, project_id, safe_asset,
            "Query parameter reflection review",
            "skipped",
            json.dumps({
                "reason": "Query string could not be safely parsed.",
                "query_values_recorded": False,
            }),
        )
        return {"parameters_reviewed": 0, "reflected_parameters": 0}

    if not parameters:
        _save_check(
            db, project_id, safe_asset,
            "Query parameter reflection review",
            "skipped",
            json.dumps({
                "reason": "URL contained no query parameters.",
                "query_values_recorded": False,
            }),
        )
        return {"parameters_reviewed": 0, "reflected_parameters": 0}

    response_text = body.decode("utf-8", errors="replace")
    sensitive_name_pattern = re.compile(
        r"password|passwd|secret|token|authorization|session|"
        r"api.?key|credential|auth.?code",
        re.IGNORECASE,
    )

    reviewed_names = []
    reflected_names = []
    redacted_count = 0

    for name, value in parameters[:100]:
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)[:80]

        if sensitive_name_pattern.search(name):
            redacted_count += 1
            continue

        if not value or len(value) < 5 or len(value) > 160:
            continue

        # Avoid recording values. Short/common and numeric-only values are
        # excluded to reduce noisy matches.
        if not any(character.isalpha() for character in value):
            continue

        reviewed_names.append(safe_name or "[unnamed]")

        if value in response_text:
            reflected_names.append(safe_name or "[unnamed]")

    result = {
        "query_parameter_count": len(parameters),
        "parameters_reviewed": len(reviewed_names),
        "reflected_parameter_names": sorted(set(reflected_names))[:50],
        "sensitive_parameter_names_omitted": redacted_count,
        "response_content_type": str(content_type or "")[:160],
        "response_truncated": bool(truncated),
        "body_bytes_reviewed": len(body),
        "query_values_recorded": False,
        "payloads_executed": False,
        "network_requests_made": 0,
        "interpretation": (
            "Reflection is an observation only. It does not establish "
            "JavaScript execution, unsafe output context, or XSS."
        ),
    }

    _save_check(
        db,
        project_id,
        safe_asset,
        "Query parameter reflection review",
        "completed",
        json.dumps(result)[:8000],
    )

    return {
        "parameters_reviewed": len(reviewed_names),
        "reflected_parameters": len(set(reflected_names)),
    }


def _analyze_api_response(
    db, project_id, url, content_type, body, truncated=False
):
    """
    Passively inspect JSON responses without storing sensitive values.

    Every invocation records an explicit outcome. Non-JSON responses are
    recorded as skipped rather than silently disappearing from coverage.
    """
    if "json" not in content_type.lower():
        _save_check(
            db,
            project_id,
            url,
            "Passive API response disclosure review",
            "skipped",
            json.dumps({
                "reason": "Response content type was not identified as JSON.",
                "content_type": content_type[:200],
                "sensitive_values_recorded": False,
            }),
        )
        return {
            "sensitive_fields": 0,
            "verbose_errors": 0,
            "json_valid": False,
            "reviewed": False,
        }

    text = body.decode("utf-8", errors="replace")
    sensitive_names = set()
    sensitive_tokens = {
        "password", "passwd", "token", "api_key", "secret",
        "client_secret", "private_key", "authorization",
    }
    sensitive_compound_names = {
        "access_token", "refresh_token", "api_key",
        "client_secret", "private_key",
    }

    try:
        payload = json.loads(text)
        json_valid = True
    except (ValueError, TypeError):
        payload = None
        json_valid = False

    if payload is not None:
        pending = [payload]
        visited = 0

        while pending and visited < 5000:
            current = pending.pop()
            visited += 1

            if isinstance(current, dict):
                for key, value in current.items():
                    normalized = re.sub(
                        r"([a-z0-9])([A-Z])", r"\1_\2", str(key)
                    ).lower()
                    tokens = {
                        part for part in re.split(r"[^a-z0-9]+", normalized)
                        if part
                    }

                    if (
                        normalized in sensitive_compound_names
                        or tokens.intersection(sensitive_tokens)
                    ) and value is not None and value != "":
                        sensitive_names.add(str(key)[:80])

                    if isinstance(value, (dict, list)):
                        pending.append(value)

            elif isinstance(current, list):
                pending.extend(
                    item for item in current
                    if isinstance(item, (dict, list))
                )

    error_patterns = (
        ("Python traceback", r"Traceback \(most recent call last\)"),
        ("Java stack trace", r"(?m)^\s*at\s+[\w.$<>]+\([^)]*:\d+\)"),
        (
            "Runtime exception detail",
            r"\b(?:NullPointerException|TypeError|ReferenceError|"
            r"UnhandledException|Fatal error|PDOException)\b",
        ),
        (
            "Database error detail",
            r"\b(?:SQLSTATE|syntax error at or near|"
            r"unclosed quotation mark|mysql_fetch|SQLiteException)\b",
        ),
        (
            "Internal source path",
            r"(?:/var/www/|/home/|/app/)[\w./-]+\.(?:py|php|js|java|rb)",
        ),
    )

    error_indicators = [
        label for label, pattern in error_patterns
        if re.search(pattern, text, re.IGNORECASE)
    ]

    if sensitive_names:
        names = sorted(sensitive_names)[:20]
        _save_finding(
            db=db,
            project_id=project_id,
            title="Potential sensitive fields in API response",
            category="API Security",
            severity="medium",
            confidence="low",
            asset=url,
            description=(
                "A JSON response contains non-empty properties whose names "
                "are commonly associated with credentials or secrets. "
                "This does not establish improper access or credential validity."
            ),
            evidence=(
                "Sensitive-looking property names only: "
                + ", ".join(names)
                + ". Values were deliberately not stored."
            ),
            remediation=(
                "Review whether each property is required by the intended "
                "client and user role. Enforce server-side object and "
                "field-level authorization, and avoid returning secrets."
            ),
        )

    if error_indicators:
        _save_finding(
            db=db,
            project_id=project_id,
            title="Verbose server error details in API response",
            category="API Security",
            severity="low",
            confidence="low",
            asset=url,
            description=(
                "The JSON response contains patterns associated with "
                "internal exceptions, database errors, or source paths."
            ),
            evidence=(
                "Indicator types: " + ", ".join(error_indicators)
                + ". Response excerpts and sensitive values were not stored."
            ),
            remediation=(
                "Return generic client-facing errors. Keep stack traces, "
                "database diagnostics, and internal paths in protected "
                "server-side logs."
            ),
        )

    # Always record the completed JSON review, including a clean result.
    _save_check(
        db,
        project_id,
        url,
        "Passive API response disclosure review",
        "completed",
        json.dumps({
            "json_valid": json_valid,
            "sensitive_property_names": sorted(sensitive_names)[:20],
            "sensitive_values_recorded": False,
            "verbose_error_indicators": error_indicators,
            "response_truncated": bool(truncated),
            "body_bytes_reviewed": len(body),
            "inspection_limit": 5000,
        }),
    )

    return {
        "sensitive_fields": len(sensitive_names),
        "verbose_errors": len(error_indicators),
        "json_valid": json_valid,
        "reviewed": True,
    }

def _ensure_guided_security_test_cases(db, project_id, target):
    cases = [
        ("SQL Injection", "Verify parameterised database queries",
         "In an authorised staging environment, review query construction and use harmless test inputs. Do not extract data or modify records."),
        ("Cross-Site Scripting", "Verify output encoding and DOM sinks",
         "Use a harmless marker in an authorised test account and verify context-aware output encoding. Do not execute payloads against other users."),
        ("CSRF", "Verify anti-CSRF protections",
         "With a controlled test account, verify token validation and Origin/Referer checks for state-changing requests. Do not submit actions to real users."),
        ("Authentication and Authorization", "Verify authentication and role boundaries",
         "Use owner and least-privilege test accounts to verify protected routes reject unauthenticated and unauthorised access."),
        ("IDOR", "Verify object ownership checks",
         "Use two test accounts and objects created by those accounts. Confirm each account can access only its own objects."),
        ("Business Logic", "Verify workflow and business invariants",
         "Use staging data to verify server-side price, quantity, role, state-transition, and ownership rules."),
        ("Race Conditions and Payments", "Verify concurrency and payment idempotency",
         "Use a payment sandbox and test transactions only. Verify duplicate requests, idempotency, and concurrent state changes without real money."),
    ]

    existing = set(db.scalars(
        select(TestCase.title).where(TestCase.project_id == project_id)
    ).all())

    for category, title, notes in cases:
        if title not in existing:
            db.add(TestCase(
                project_id=project_id,
                category=category,
                title=title,
                target=target,
                status="Planned",
                notes=notes,
            ))


def run_website_analysis(
    db,
    project_id,
    start_url,
    max_pages=15,
    delay_seconds=0.75,
    stop_event=None,
    progress_callback=None,
):
    """
    Run a bounded website assessment against an approved HTTPS target.

    Only same-host GET requests are made.
    Redirects are not followed.
    """

    project = db.get(Project, project_id)

    if not project or project.status == "deleted":
        raise ValueError("Archived or unavailable projects cannot be scanned.")

    if not project.scope_approved:
        raise ValueError("Project scope has not been approved.")

    if not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}.")

    delay_seconds = max(MIN_DELAY_SECONDS, min(float(delay_seconds), 5.0))

    parsed = validate_target(db, project_id, start_url)

    if parsed.scheme.lower() != "https":
        raise ValueError("The initial website URL must use HTTPS.")

    if parsed.port not in (None, 443):
        raise ValueError("Only the standard HTTPS port is supported.")

    origin = f"https://{parsed.hostname.lower()}"
    start_url = _is_safe_page(start_url, origin)

    if not start_url:
        raise ValueError("The starting URL is not eligible for crawling.")

    assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project_id,
            ScopeAsset.approved.is_(True),
            ScopeAsset.included.is_(True),
        )
    ).all()

    if not assets:
        raise ValueError("No approved and included scope assets exist.")

    _ensure_guided_security_test_cases(db, project_id, start_url)

    log_activity(
        db,
        project_id,
        "Website analysis started",
        f"Target: {start_url}; page limit: {max_pages}; GET-only mode.",
    )

    queue = deque([start_url])
    visited = set()

    initial_finding_count = db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.project_id == project_id,
            Finding.status == "potential",
        )
    ) or 0

    stats = {
        "pages_checked": 0,
        "requests_attempted": 0,
        "total_requests": 0,
        "robots_requests": 0,
        "endpoints_discovered": 0,
        "findings_created": 0,
        "requests_failed": 0,
        "request_limit_reached": False,
        "stopped": False,
        "tls_verified": False,
        "exposure_probes_attempted": 0,
        "exposure_indicators": 0,
        "client_routes_discovered": 0,
        "javascript_assets_checked": 0,
        "source_maps_discovered": 0,
        "client_security_patterns_detected": 0,
        "sensitive_markers_detected": 0,
        "html_forms_reviewed": 0,
        "password_get_forms_detected": 0,
        "external_forms_detected": 0,
        "sensitive_metadata_indicators": 0,
        "development_indicators": 0,
        "mixed_content_pages": 0,
        "insecure_form_pages": 0,
        "csrf_candidate_forms_detected": 0,
        "sql_error_indicators_detected": 0,
        "api_sensitive_fields_detected": 0,
        "api_verbose_errors_detected": 0,
        "openapi_documents_reviewed": 0,
        "openapi_operations_reviewed": 0,
        "openapi_operations_registered": 0,
        "openapi_operations_skipped": 0,
        "openapi_identity_parameters_detected": 0,
        "openapi_sensitive_parameters_detected": 0,
        "openapi_body_fields_discovered": 0,
        "openapi_operations_without_security": 0,
    }

    def report_progress(message):
        if progress_callback is None:
            return
        try:
            # Reserve the final 5% for evidence validation and job finalization.
            percent = min(
                94,
                int(stats["total_requests"] * 100 / max_pages),
            )
            progress_callback(percent, message)
        except Exception:
            # A UI callback must never interrupt the assessment.
            pass

    robots = RobotFileParser()
    robots_url = origin + "/robots.txt"
    robots_available = False

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
        "Origin": DIAGNOSTIC_ORIGIN,
    }

    transport = PinnedHTTPTransport(urlsplit(origin).hostname)
    transport.validate_dns()

    with httpx.Client(
        transport=transport,
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        headers=headers,
    ) as client:

        # Retrieve robots.txt once and use it to guide crawling.
        try:
            if stop_event is not None and stop_event.wait(delay_seconds):
                stats["stopped"] = True
                robots.parse([])
            else:
                if stats["total_requests"] < max_pages:
                    stats["robots_requests"] += 1
                    stats["total_requests"] += 1
                    robots_response = _read_limited_response(client, robots_url)
                else:
                    stats["request_limit_reached"] = True
                    robots.parse([])
                stats["tls_verified"] = True
                _save_check(
                    db, project_id, robots_url,
                    "HTTPS TLS certificate verification",
                    "completed",
                    "HTTPS connection succeeded with certificate-chain "
                    "and hostname verification enabled. This does not "
                    "constitute a full TLS protocol or cipher-suite audit."
                )

                if robots_response["status"] == 200:
                    robots.parse(
                        robots_response["body"].decode(
                            "utf-8", errors="replace"
                        ).splitlines()
                    )
                    robots_available = True
                else:
                    robots.parse([])

        except Exception:
            robots.parse([])
            if stop_event is not None and stop_event.is_set():
                stats["stopped"] = True

        javascript_seen = set()

        while (
            queue
            and stats["total_requests"] < max_pages
            and not stats["stopped"]
        ):
            url = queue.popleft()

            if url in visited:
                continue

            visited.add(url)

            try:
                validate_target(db, project_id, url)

                if robots_available and not robots.can_fetch(USER_AGENT, url):
                    _save_check(
                        db,
                        project_id,
                        url,
                        "Robots policy",
                        "skipped",
                        "Page disallowed by robots.txt.",
                    )
                    db.commit()
                    report_progress(
                        f"Skipped by robots.txt; "
                        f"{stats['pages_checked']} pages checked"
                    )
                    continue

                # Enforce spacing between every page GET, including failures.
                if stats["total_requests"] > 0:
                    if stop_event is not None:
                        if stop_event.wait(delay_seconds):
                            stats["stopped"] = True
                            break
                    else:
                        time.sleep(delay_seconds)

                if stop_event is not None and stop_event.is_set():
                    stats["stopped"] = True
                    break

                # Failed page requests consume the same bounded request budget.
                stats["requests_attempted"] += 1
                stats["total_requests"] += 1
                response = _read_limited_response(client, url)

                status = response["status"]
                response_headers = response["headers"]
                content_type = response_headers.get(
                    "content-type", ""
                ).lower()

                # Redirects are recorded, never followed automatically.
                if 300 <= status < 400:
                    _save_check(
                        db,
                        project_id,
                        url,
                        "HTTP response",
                        "completed",
                        f"HTTP {status}; redirect not followed.",
                    )
                    stats["pages_checked"] += 1
                    db.commit()
                    report_progress(
                        f"Redirect recorded, not followed; "
                        f"{stats['total_requests']}/{max_pages} total requests; "
                        f"{stats['pages_checked']} pages checked"
                    )
                    continue

                api_stats = _analyze_api_response(
                    db,
                    project_id,
                    url,
                    content_type,
                    response["body"],
                    truncated=response["truncated"],
                )

                # Assess existing query inputs against this already-fetched
                # response. This performs no additional network requests.
                _analyze_reflected_query_inputs(
                    db,
                    project_id,
                    url,
                    content_type,
                    response["body"],
                    truncated=response["truncated"],
                )
                stats["api_sensitive_fields_detected"] += (
                    api_stats["sensitive_fields"]
                )
                stats["api_verbose_errors_detected"] += (
                    api_stats["verbose_errors"]
                )

                missing_headers = _analyze_headers(
                    db, project_id, url, response_headers
                )

                _analyze_policy_headers(
                    db, project_id, url, response_headers
                )

                _analyze_cors(
                    db, project_id, url, response_headers
                )

                _analyze_cookies(
                    db,
                    project_id,
                    url,
                    response["cookies"],
                )

                server = response_headers.get("server", "not disclosed")
                powered_by = response_headers.get(
                    "x-powered-by", "not disclosed"
                )

                details = {
                    "http_status": status,
                    "content_type": content_type,
                    "missing_security_headers": missing_headers,
                    "server_header": server,
                    "x_powered_by": powered_by,
                    "response_truncated": response["truncated"],
                    "redirects_followed": False,
                }

                _save_check(
                    db,
                    project_id,
                    url,
                    "Automated website response analysis",
                    "completed",
                    json.dumps(details, indent=2),
                )

                if _save_endpoint(db, project_id, url):
                    stats["endpoints_discovered"] += 1

                stats["pages_checked"] += 1

                # Crawl only HTML links on the same approved host.
                if "text/html" in content_type:
                    html = response["body"].decode(
                        "utf-8", errors="replace"
                    )

                    parser = LinkParser()
                    parser.feed(html)

                    html_stats = _analyze_html_security(
                        db, project_id, url, parser
                    )
                    stats["html_forms_reviewed"] += html_stats["forms_reviewed"]
                    stats["password_get_forms_detected"] += html_stats["password_get_forms"]
                    stats["external_forms_detected"] += html_stats["external_forms"]
                    stats["sensitive_metadata_indicators"] += html_stats["sensitive_metadata"]
                    stats["development_indicators"] += html_stats["development_indicators"]
                    stats["mixed_content_pages"] += html_stats["mixed_content_pages"]
                    stats["insecure_form_pages"] += html_stats["insecure_form_pages"]
                    stats["csrf_candidate_forms_detected"] += html_stats["csrf_candidate_forms"]
                    stats["sql_error_indicators_detected"] += html_stats["sql_error_indicators"]

                    stats["client_routes_discovered"] += _discover_client_routes(
                        db, project_id, url, origin, parser, html
                    )
                    stats["sensitive_markers_detected"] += _analyze_client_content(
                        db, project_id, url, html
                    )

                    stats["client_security_patterns_detected"] += (
                        _analyze_client_security_patterns(
                            db, project_id, url, html
                        )
                    )

                    # Retrieve a bounded number of same-host JavaScript assets.
                    for script_url in parser.script_urls[:20]:
                        if (
                            stats["total_requests"] >= max_pages
                            or stats["stopped"]
                        ):
                            break

                        asset_url = _normalize_url(urljoin(url, script_url))
                        if not asset_url or asset_url in javascript_seen:
                            continue

                        asset_parts = urlsplit(asset_url)
                        origin_parts = urlsplit(origin)
                        if (
                            asset_parts.hostname != origin_parts.hostname
                            or asset_parts.port not in (None, 443)
                            or asset_parts.scheme != "https"
                        ):
                            continue

                        if any(
                            word in asset_parts.path.lower().split("/")
                            for word in SKIP_PATH_WORDS
                        ):
                            continue

                        javascript_seen.add(asset_url)

                        try:
                            validate_target(db, project_id, asset_url)
                        except ValueError:
                            continue

                        if robots_available and not robots.can_fetch(
                            USER_AGENT, asset_url
                        ):
                            _save_check(
                                db, project_id, asset_url,
                                "JavaScript asset robots policy",
                                "skipped",
                                "Asset disallowed by robots.txt.",
                            )
                            continue

                        if stop_event is not None and stop_event.wait(delay_seconds):
                            stats["stopped"] = True
                            break
                        elif stop_event is None and stats["total_requests"] > 0:
                            time.sleep(delay_seconds)

                        if stop_event is not None and stop_event.is_set():
                            stats["stopped"] = True
                            break

                        stats["requests_attempted"] += 1
                        stats["total_requests"] += 1

                        try:
                            asset_response = _read_limited_response(
                                client, asset_url
                            )
                            asset_status = asset_response["status"]
                            asset_type = asset_response["headers"].get(
                                "content-type", ""
                            ).lower()

                            if 300 <= asset_status < 400:
                                _save_check(
                                    db, project_id, asset_url,
                                    "JavaScript asset review", "skipped",
                                    "Redirect returned; it was not followed.",
                                )
                                continue

                            if asset_status != 200 or not any(
                                kind in asset_type
                                for kind in (
                                    "javascript", "ecmascript",
                                )
                            ):
                                _save_check(
                                    db, project_id, asset_url,
                                    "JavaScript asset review", "skipped",
                                    f"HTTP {asset_status}; response was not "
                                    "identified as JavaScript.",
                                )
                                continue

                            js_text = asset_response["body"].decode(
                                "utf-8", errors="replace"
                            )

                            stats["source_maps_discovered"] += (
                                _discover_source_maps(
                                    db, project_id, asset_url, origin, js_text
                                )
                            )

                            if _save_endpoint(
                                db, project_id, asset_url,
                                "Client-side JavaScript asset",
                            ):
                                stats["endpoints_discovered"] += 1

                            stats["javascript_assets_checked"] += 1
                            stats["client_routes_discovered"] += (
                                _discover_client_routes(
                                    db, project_id, asset_url, origin,
                                    LinkParser(), js_text,
                                )
                            )
                            stats["sensitive_markers_detected"] += (
                                _analyze_client_content(
                                    db, project_id, asset_url, js_text
                                )
                            )
                            stats["client_security_patterns_detected"] += (
                                _analyze_client_security_patterns(
                                    db, project_id, asset_url, js_text
                                )
                            )
                            _save_check(
                                db, project_id, asset_url,
                                "JavaScript asset review", "completed",
                                "Bounded JavaScript content reviewed. "
                                "No script was executed.",
                            )

                        except Exception as asset_exc:
                            stats["requests_failed"] += 1
                            _save_check(
                                db, project_id, asset_url,
                                "JavaScript asset review", "failed",
                                str(asset_exc)[:1000],
                            )

                    for href in parser.links:
                        absolute = urljoin(url, href)
                        candidate = _is_safe_page(absolute, origin)

                        if not candidate or candidate in visited:
                            continue

                        try:
                            validate_target(db, project_id, candidate)
                            if candidate not in queue:
                                queue.append(candidate)
                        except ValueError:
                            continue

                db.flush()

                db.commit()

                current_findings = db.scalar(
                    select(func.count()).select_from(Finding).where(
                        Finding.project_id == project_id,
                        Finding.status == "potential",
                    )
                ) or 0

                stats["findings_created"] = max(
                    0, current_findings - initial_finding_count
                )

                report_progress(
                    f"Attempted {stats['total_requests']}/{max_pages} total requests; "
                    f"{stats['pages_checked']} pages checked; "
                    f"{stats['javascript_assets_checked']} JS assets; "
                    f"{stats['client_routes_discovered']} client routes; "
                    f"{stats['findings_created']} new potential findings"
                )

            except Exception as exc:
                if stop_event is not None and stop_event.is_set():
                    stats["stopped"] = True
                    break

                stats["requests_failed"] += 1

                _save_check(
                    db,
                    project_id,
                    url,
                    "Automated website response analysis",
                    "failed",
                    str(exc)[:1000],
                )
                db.commit()
                report_progress(
                    f"Request failed; {stats['total_requests']}/{max_pages} total requests, "
                    f"{stats['pages_checked']} pages checked, "
                    f"{stats['requests_failed']} request(s) failed"
                )


        # A fixed set of conventional paths; never brute-force directories.
        # Responses are inspected for indicators, but secret values are not saved.
        for probe_path in EXPOSURE_PROBE_PATHS:
            if stats["total_requests"] >= max_pages:
                break

            if stop_event is not None and stop_event.is_set():
                stats["stopped"] = True
                break

            probe_url = origin + probe_path

            try:
                validate_target(db, project_id, probe_url)

                if stats["total_requests"] > 0:
                    if stop_event is not None:
                        if stop_event.wait(delay_seconds):
                            stats["stopped"] = True
                            break
                    else:
                        time.sleep(delay_seconds)

                if stop_event is not None and stop_event.is_set():
                    stats["stopped"] = True
                    break

                if stats["total_requests"] >= max_pages:
                    break

                stats["exposure_probes_attempted"] += 1
                stats["total_requests"] += 1
                probe = _read_limited_response(client, probe_url)
                status = probe["status"]
                body = probe["body"].decode("utf-8", errors="replace")
                indicator = None

                if status == 200 and probe_path == "/.env":
                    if re.search(
                        r"(?im)^\s*(?:APP_KEY|DB_PASSWORD|DATABASE_URL|"
                        r"SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY)\s*=",
                        body,
                    ):
                        indicator = "Environment-variable configuration markers"

                elif status == 200 and probe_path == "/.git/HEAD":
                    if re.match(r"(?im)^\s*ref:\s+refs/", body):
                        indicator = "Git repository HEAD reference"

                elif status == 200 and probe_path == "/actuator/env":
                    if "propertySources" in body and (
                        "activeProfiles" in body or '"property"' in body
                    ):
                        indicator = "Spring actuator environment metadata"

                elif status == 200 and probe_path == "/config.json":
                    # Reserved for future use; not requested in this probe set.
                    pass

                if indicator:
                    stats["exposure_indicators"] += 1
                    _save_finding(
                        db=db,
                        project_id=project_id,
                        title=f"Potential exposed sensitive resource: {probe_path}",
                        category="Sensitive Data Exposure",
                        severity="high",
                        confidence="medium",
                        asset=probe_url,
                        description=(
                            "A conventional resource returned content matching "
                            "a sensitive configuration or repository marker. "
                            "The response was not copied into the finding; "
                            "manual authorized verification is required."
                        ),
                        evidence=(
                            f"HTTP {status}; detected indicator: {indicator}. "
                            "Sensitive response contents were not retained."
                        ),
                        remediation=(
                            "Restrict access to configuration and repository "
                            "metadata. Remove sensitive files from the web root, "
                            "rotate any exposed credentials, and review access logs."
                        ),
                    )

                elif status == 200 and probe_path in (
                    "/openapi.json", "/swagger.json"
                ):
                    api_notes = []
                    try:
                        document = json.loads(body[:500000])
                        if isinstance(document, dict):
                            stats["openapi_documents_reviewed"] += 1
                            paths = document.get("paths", {})
                            schemas = document.get("components", {}).get(
                                "schemas", {}
                            )
                            api_notes.append(
                                f"Document type: {document.get('openapi', document.get('swagger', 'unknown'))}"
                            )
                            api_notes.append(
                                f"Documented paths: {len(paths) if isinstance(paths, dict) else 0}"
                            )
                            api_notes.append(
                                f"Component schemas: {len(schemas) if isinstance(schemas, dict) else 0}"
                            )

                            servers = document.get("servers", [])
                            if isinstance(servers, list):
                                server_urls = [
                                    item.get("url", "")
                                    for item in servers
                                    if isinstance(item, dict)
                                ]
                                insecure_servers = [
                                    value for value in server_urls
                                    if isinstance(value, str)
                                    and value.lower().startswith("http://")
                                ]
                                if insecure_servers:
                                    api_notes.append(
                                        f"Insecure HTTP server URLs: {len(insecure_servers)}"
                                    )

                            global_security = document.get("security")
                            security_schemes = (
                                document.get("components", {}).get(
                                    "securitySchemes", {}
                                )
                            )
                            if global_security is None:
                                api_notes.append(
                                    "No document-level security requirement declared"
                                )
                            if not security_schemes:
                                api_notes.append(
                                    "No component security schemes declared"
                                )

                            operation_count = 0
                            operations_without_security = 0
                            if isinstance(paths, dict):
                                for path_item in paths.values():
                                    if not isinstance(path_item, dict):
                                        continue
                                    for method in (
                                        "get", "post", "put", "patch",
                                        "delete", "options", "head", "trace",
                                    ):
                                        operation = path_item.get(method)
                                        if not isinstance(operation, dict):
                                            continue
                                        operation_count += 1
                                        if (
                                            "security" not in operation
                                            and global_security is None
                                        ) or operation.get("security") == []:
                                            operations_without_security += 1

                            api_notes.append(
                                f"Operations reviewed: {operation_count}"
                            )
                            api_notes.append(
                                f"Operations without declared security: "
                                f"{operations_without_security}"
                            )
                            # Inventory documented operations individually.
                            # Only same-origin HTTPS server URLs are accepted.
                            documented_operations_registered = 0
                            documented_operations_skipped = 0
                            operation_methods = {
                                "get", "post", "put", "patch",
                                "delete", "options", "head",
                            }

                            server_values = []
                            if isinstance(servers, list):
                                for server in servers[:10]:
                                    if isinstance(server, dict):
                                        value = server.get("url")
                                        if isinstance(value, str) and value.strip():
                                            server_values.append(value.strip())

                            if not server_values:
                                server_values = [origin]

                            server_bases = []
                            for server_value in server_values:
                                try:
                                    base_url = urljoin(
                                        origin.rstrip("/") + "/",
                                        server_value,
                                    )
                                    base_parts = urlsplit(base_url)
                                    origin_parts = urlsplit(origin)
                                    if (
                                        base_parts.scheme == "https"
                                        and base_parts.hostname == origin_parts.hostname
                                        and base_parts.port in (None, 443)
                                        and base_parts.username is None
                                        and base_parts.password is None
                                    ):
                                        server_bases.append(base_url.rstrip("/") + "/")
                                except (ValueError, TypeError):
                                    continue

                            if isinstance(paths, dict):
                                for documented_path, path_item in list(paths.items())[:500]:
                                    if (
                                        not isinstance(documented_path, str)
                                        or not documented_path.startswith("/")
                                        or not isinstance(path_item, dict)
                                    ):
                                        continue

                                    for method_name in operation_methods:
                                        operation = path_item.get(method_name)
                                        if not isinstance(operation, dict):
                                            continue

                                        registered = False
                                        for server_base in server_bases:
                                            candidate_url = urljoin(
                                                server_base,
                                                documented_path.lstrip("/"),
                                            )
                                            operation_id = operation.get(
                                                "operationId", ""
                                            )
                                            metadata = _openapi_operation_metadata(
                                                document, path_item, operation,
                                                documented_path,
                                            )
                                            stats["openapi_operations_reviewed"] += 1
                                            stats["openapi_identity_parameters_detected"] += len(
                                                metadata["identity_parameter_names"]
                                            )
                                            stats["openapi_sensitive_parameters_detected"] += len(
                                                metadata["sensitive_parameter_names"]
                                            )
                                            stats["openapi_body_fields_discovered"] += len(
                                                metadata["request_body_field_names"]
                                            )
                                            if not metadata["security_declared"]:
                                                stats["openapi_operations_without_security"] += 1

                                            metadata_note = json.dumps(
                                                metadata, ensure_ascii=True
                                            )[:2200]
                                            source_note = (
                                                f"Documented in {probe_url}; "
                                                f"operationId={str(operation_id)[:120]}. "
                                                f"OpenAPI metadata: {metadata_note}. "
                                                "Names and declarations only; no "
                                                "operation request was sent."
                                            )
                                            try:
                                                if _save_endpoint(
                                                    db,
                                                    project_id,
                                                    candidate_url,
                                                    "OpenAPI documented API operation",
                                                    method=method_name.upper(),
                                                    notes=source_note,
                                                ):
                                                    stats["endpoints_discovered"] += 1

                                                _record_openapi_operation_assessment(
                                                    db,
                                                    project_id,
                                                    candidate_url,
                                                    method_name.upper(),
                                                    documented_path,
                                                    operation_id,
                                                    metadata,
                                                )

                                                registered = True
                                                break
                                            except ValueError:
                                                continue

                                        if registered:
                                            documented_operations_registered += 1
                                            stats["openapi_operations_registered"] += 1
                                        else:
                                            documented_operations_skipped += 1
                                            stats["openapi_operations_skipped"] += 1

                            api_notes.append(
                                "Documented operations registered: "
                                f"{documented_operations_registered}"
                            )
                            api_notes.append(
                                "Documented operations skipped by scope or validation: "
                                f"{documented_operations_skipped}"
                            )

                            serialized = json.dumps(document).lower()
                            sensitive_terms = (
                                "password", "secret", "token",
                                "private_key", "internal", "admin",
                            )
                            markers = [
                                term for term in sensitive_terms
                                if term in serialized
                            ]
                            if markers:
                                api_notes.append(
                                    "Sensitive-name markers: " + ", ".join(markers)
                                )
                        else:
                            api_notes.append("JSON root is not an object")
                    except (ValueError, TypeError):
                        api_notes.append("Response was not valid JSON")

                    _save_check(
                        db, project_id, probe_url,
                        "Public API documentation discovery",
                        "completed",
                        (
                            "A conventional API documentation path returned HTTP 200. "
                            "Public documentation is not automatically a vulnerability. "
                            + "; ".join(api_notes)
                            + ". Schema names are indicators only; values and "
                            "credential validity were not verified."
                        )[:8000],
                    )

                else:
                    _save_check(
                        db, project_id, probe_url,
                        f"Exposure probe {probe_path}",
                        "completed",
                        f"HTTP {status}; no known exposure indicator detected."
                    )

                db.commit()

            except Exception as exc:
                if stop_event is not None and stop_event.is_set():
                    stats["stopped"] = True
                    break

                _save_check(
                    db, project_id, probe_url,
                    f"Exposure probe {probe_path}",
                    "failed",
                    str(exc)[:800],
                )
                db.commit()

    probes_remaining = (
        stats["exposure_probes_attempted"] < len(EXPOSURE_PROBE_PATHS)
    )
    stats["request_limit_reached"] = bool(
        stats["total_requests"] >= max_pages
        and (bool(queue) or probes_remaining)
        and not stats["stopped"]
    )

    current_findings = db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.project_id == project_id,
            Finding.status == "potential",
        )
    ) or 0

    stats["findings_created"] = max(
        0, current_findings - initial_finding_count
    )

    if stop_event is not None and stop_event.is_set():
        stats["stopped"] = True

    activity_title = (
        "Website analysis stopped"
        if stats["stopped"]
        else "Website analysis completed"
    )

    log_activity(
        db,
        project_id,
        activity_title,
        json.dumps(stats),
    )

    return stats
