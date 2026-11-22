"""Provider-aware, conservative bug bounty policy intelligence.

The parser extracts candidates and policy rules from public or imported
programme text. It never authorizes assets, approves scope, or contacts
candidate targets. Ambiguous and path-limited scope remains unapproved.
"""

import hashlib
import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9_-])"
    r"(\*\.)?"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})"
    r"(?![a-z0-9_-])"
)
URL_RE = re.compile(r"(?i)https?://[^\s<>\"']{1,2048}")
CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.])")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w./])")

PROVIDERS = {
    "hackerone": {"domains": ("hackerone.com",), "name": "HackerOne"},
    "bugcrowd": {"domains": ("bugcrowd.com",), "name": "Bugcrowd"},
    "intigriti": {"domains": ("intigriti.com",), "name": "Intigriti"},
    "yeswehack": {"domains": ("yeswehack.com",), "name": "YesWeHack"},
    "immunefi": {"domains": ("immunefi.com",), "name": "Immunefi"},
    "federacy": {"domains": ("federacy.com",), "name": "Federacy"},
    "openbugbounty": {"domains": ("openbugbounty.org",), "name": "OpenBugBounty"},
    "hackenproof": {"domains": ("hackenproof.com",), "name": "HackenProof"},
    "huntr": {"domains": ("huntr.com",), "name": "huntr"},
    "patchstack": {"domains": ("patchstack.com",), "name": "Patchstack"},
    "yogosha": {"domains": ("yogosha.com",), "name": "Yogosha"},
}

EXCLUDED_PATTERNS = (
    r"\bout\s+of\s+scope\b",
    r"\bexcluded?\b",
    r"\bnot\s+in\s+scope\b",
    r"\bprohibited\s+assets?\b",
    r"\bdo\s+not\s+test\b",
    r"\bnot\s+eligible\b",
    r"\bexplicitly\s+excluded\b",
    r"\bno\s+testing\b",
)
INCLUDED_PATTERNS = (
    r"\bin\s+scope\b",
    r"\bincluded\s+assets?\b",
    r"\beligible\s+assets?\b",
    r"\btargets?\s+in\s+scope\b",
    r"\bassets?\s+covered\s+by\s+this\s+program\b",
    r"\btesting\s+is\s+permitted\b",
)

SECTION_EXCLUDED = re.compile(
    r"^(?:out[- ]of[- ]scope(?:\s+assets?)?|excluded(?:\s+assets?)?|"
    r"prohibited(?:\s+assets?)?|not\s+in\s+scope(?:\s+assets?)?)\s*:?$",
    re.I,
)
SECTION_INCLUDED = re.compile(
    r"^(?:in[- ]scope(?:\s+assets?)?|included(?:\s+assets?)?|"
    r"eligible(?:\s+(?:assets?|targets?))?|scope\s+assets?|"
    r"targets?\s+in\s+scope)\s*:?$",
    re.I,
)

POLICY_TOPICS = {
    "testing_restrictions": (
        "rate limit", "denial of service", "automated scanner",
        "social engineering", "destructive", "brute force",
        "physical security", "spam", "availability testing",
    ),
    "disclosure": (
        "responsible disclosure", "coordinated disclosure",
        "public disclosure", "disclosure policy",
    ),
    "authentication": (
        "authentication", "test account", "account required",
        "two-factor", "multi-factor",
    ),
    "vulnerability_eligibility": (
        "out of scope", "in scope", "not eligible",
        "excluded", "impact",
    ),
    "safe_harbor": (
        "safe harbor", "good faith", "authorization",
        "legal protection",
    ),
}

RULE_PATTERNS = {
    "prohibited_activities": (
        r"\bdenial[- ]of[- ]service\b", r"\bddos\b",
        r"\bbrute[- ]force\b", r"\bsocial engineering\b",
        r"\bphishing\b", r"\bspam(?:ming)?\b",
        r"\bphysical attacks?\b", r"\bdestructive testing\b",
        r"\bautomated scanners?\b", r"\bload testing\b",
        r"\bavailability testing\b",
    ),
    "authentication_requirements": (
        r"\btest accounts?\b", r"\bprovided credentials\b",
        r"\bmulti[- ]factor authentication\b",
        r"\baccount registration\b",
    ),
    "disclosure_requirements": (
        r"\bresponsible disclosure\b", r"\bcoordinated disclosure\b",
        r"\bdo not publicly disclose\b", r"\bpublic disclosure\b",
    ),
    "rate_limit_rules": (
        r"\b\d+\s*(?:requests?|reqs?)\s*(?:per|/)\s*(?:second|minute|hour)\b",
        r"\brate limit\b", r"\brequest rate\b",
        r"\brequests per second\b",
    ),
    "data_handling_rules": (
        r"\bpersonal data\b", r"\bpersonally identifiable\b",
        r"\bpii\b", r"\bdelete test data\b",
        r"\bdo not access real user data\b",
    ),
    "vulnerability_eligibility": (
        r"\bnot eligible\b", r"\bineligible\b",
        r"\bnot accepted\b", r"\baccepted vulnerabilities?\b",
        r"\beligible\b.{0,80}\b(?:reports?|vulnerabilities|issues)\b",
        r"\bvalid vulnerability reports?\b",
        r"\bout of scope\b",
    ),
    "reward_and_severity": (
        r"\bbounty\b", r"\breward(?:s|ed)?\b",
        r"\bpayout\b", r"\bcvss\b",
        r"\bseverity levels?\b", r"\bcritical severity\b",
    ),
}


def identify_provider(programme_url):
    """Identify a known platform by hostname; unknown providers use generic parsing."""
    host = (urlparse(programme_url).hostname or "").lower().rstrip(".")
    for provider_id, details in PROVIDERS.items():
        if any(host == domain or host.endswith("." + domain)
               for domain in details["domains"]):
            return {
                "id": provider_id,
                "name": details["name"],
                "confidence": "high",
                "adapter_available": False,
                "analysis_mode": "generic_policy_parser",
            }
    return {
        "id": "unknown",
        "name": "Unknown / direct program",
        "confidence": "low",
        "adapter_available": False,
        "analysis_mode": "generic_policy_parser",
    }


def _split_units(policy_text):
    """Keep policy list/table boundaries and split compact semicolon clauses."""
    units = []
    for raw_line in str(policy_text).replace("\r", "\n").split("\n"):
        line = re.sub(r"\s+", " ", raw_line).strip()
        if not line:
            continue
        # A single scraped paragraph may contain both inclusion and exclusion.
        parts = re.split(r"\s*[;|]\s*|\s+•\s+", line)
        units.extend(part.strip(" -\t") for part in parts if part.strip(" -\t"))
    return units


def _section_state(unit, current):
    raw = unit.strip()
    heading = re.sub(r"^#+\s*", "", raw).strip().rstrip(":").strip()
    if SECTION_EXCLUDED.fullmatch(heading):
        return "excluded"
    if SECTION_INCLUDED.fullmatch(heading):
        return "included_candidate"
    # Do not let an old scope heading leak into unrelated policy sections.
    if raw.startswith("#") or raw.endswith(":") or (
        len(heading) <= 80 and heading.isupper() and len(heading) >= 3
    ):
        return ""
    if re.fullmatch(
        r"(?:program|programme|policy|rules|restrictions|eligibility|"
        r"disclosure|safe harbor|testing guidelines)",
        heading,
        re.I,
    ):
        return ""
    return current


def _classify_context(context, section=""):
    text = str(context or "").lower()
    if any(re.search(pattern, text) for pattern in EXCLUDED_PATTERNS):
        return "excluded", "medium"
    if section == "excluded":
        return "excluded", "medium"
    if any(re.search(pattern, text) for pattern in INCLUDED_PATTERNS):
        return "included_candidate", "medium"
    if section == "included_candidate":
        return "included_candidate", "medium"
    return "ambiguous", "low"


def _record_asset(records, asset, asset_type, disposition, confidence, evidence):
    existing = records.get(asset)
    if existing is None:
        records[asset] = {
            "asset": asset,
            "type": asset_type,
            "disposition": disposition,
            "confidence": confidence,
            "evidence": [evidence[:800]] if evidence else [],
        }
        return
    # An explicit exclusion always wins over any conflicting inclusion clue.
    if disposition == "excluded":
        existing["disposition"] = "excluded"
        existing["confidence"] = confidence
    elif disposition == "included_candidate" and existing["disposition"] != "excluded":
        existing["disposition"] = "included_candidate"
        existing["confidence"] = confidence
    if evidence and evidence[:800] not in existing["evidence"]:
        existing["evidence"].append(evidence[:800])


def _extract_assets(policy_text, programme_url):
    units = _split_units(policy_text)
    records = {}
    provider_host = (urlparse(programme_url).hostname or "").lower().rstrip(".")
    section = ""

    for unit in units:
        section = _section_state(unit, section)
        if SECTION_EXCLUDED.fullmatch(re.sub(r"^#+\s*", "", unit).strip().rstrip(":").strip()):
            continue
        if SECTION_INCLUDED.fullmatch(re.sub(r"^#+\s*", "", unit).strip().rstrip(":").strip()):
            continue

        disposition, confidence = _classify_context(unit, section)

        # Preserve full URL paths: a host-only scope record would broaden access.
        url_spans = []
        for match in URL_RE.finditer(unit):
            raw_url = match.group(0).rstrip(".,);]")
            try:
                parsed = urlparse(raw_url)
                host = (parsed.hostname or "").lower().rstrip(".")
                if not host or host == provider_host:
                    continue
                exact_https_origin = (
                    parsed.scheme.lower() == "https"
                    and parsed.port in (None, 443)
                    and parsed.path in ("", "/")
                    and not parsed.query
                )
                if exact_https_origin:
                    asset = host
                    asset_type = "hostname"
                else:
                    asset = raw_url
                    asset_type = (
                        "url_path"
                        if parsed.path not in ("", "/") or parsed.query
                        else "url"
                    )
                _record_asset(records, asset, asset_type, disposition, confidence, unit)
                url_spans.append(match.span())
            except ValueError:
                continue

        for match in DOMAIN_RE.finditer(unit):
            if any(start <= match.start() < end for start, end in url_spans):
                continue
            wildcard = bool(match.group(1))
            hostname = match.group(2).lower().rstrip(".")
            if hostname == provider_host:
                continue
            asset = ("*." if wildcard else "") + hostname
            _record_asset(
                records, asset,
                "wildcard_hostname" if wildcard else "hostname",
                disposition, confidence, unit,
            )

        for match in CIDR_RE.finditer(unit):
            try:
                network = ipaddress.ip_network(match.group(0), strict=False)
            except ValueError:
                continue
            _record_asset(records, str(network), "cidr_network", disposition, confidence, unit)

        # Standalone IPs are candidates; avoid duplicating addresses in CIDRs.
        cidr_spans = [m.span() for m in CIDR_RE.finditer(unit)]
        for match in IPV4_RE.finditer(unit):
            if any(start <= match.start() < end for start, end in cidr_spans):
                continue
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            _record_asset(records, str(address), "ip_address", disposition, confidence, unit)

    return sorted(records.values(), key=lambda item: (item["disposition"], item["asset"]))


def _extract_topics(policy_text):
    lowered = policy_text.lower()
    return {
        topic: [phrase for phrase in phrases if phrase in lowered]
        for topic, phrases in POLICY_TOPICS.items()
        if any(phrase in lowered for phrase in phrases)
    }


def _extract_policy_clues(policy_text):
    keys = (
        "rate limit", "automated scanner", "denial of service",
        "social engineering", "out of scope", "in scope",
        "authentication", "disclosure", "safe harbor", "test account",
    )
    clues = {}
    for key in keys:
        matches = list(re.finditer(re.escape(key), policy_text, re.I))
        if matches:
            clues[key] = [
                policy_text[max(0, match.start() - 120):
                            min(len(policy_text), match.end() + 220)]
                for match in matches[:8]
            ]
    return clues


def _extract_rules(policy_text):
    sentences = [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+|\n+", policy_text)
        if item.strip()
    ]
    rules = {}
    for category, patterns in RULE_PATTERNS.items():
        found = []
        for sentence in sentences:
            if any(re.search(pattern, sentence, re.I) for pattern in patterns):
                compact = re.sub(r"\s+", " ", sentence).strip()
                if compact not in found:
                    found.append(compact[:1000])
        if found:
            rules[category] = found[:50]
    return rules


def derive_policy_execution_controls(policy_text):
    """Translate explicit programme restrictions into conservative worker controls.

    An ambiguous restriction is never treated as permission to exceed a stated
    rate. This parser only disables automated active crawling when a clear
    prohibition is present; it never grants authorization.
    """
    text = str(policy_text or "")
    sentences = [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+|\n+", text)
        if item.strip()
    ]

    automated_prohibition = re.compile(
        r"(?:\b(?:no|without)\s+(?:the\s+use\s+of\s+)?(?:any\s+)?"
        r"(?:automated|automatic)\s+(?:scanners?|scanning|testing|tools?)\b)"
        r"|(?:\b(?:do not|must not|shall not|may not|never)\s+"
        r"(?:use|run|perform|conduct|operate)\b.{0,100}\b"
        r"(?:automated|automatic|scanner|scanning|tools?)\b)"
        r"|(?:\b(?:automated|automatic)\s+(?:scanners?|scanning|testing|tools?)\b"
        r".{0,100}\b(?:prohibited|forbidden|not allowed|not permitted|disallowed)\b)"
        re.I,
    )
    prohibited_sentences = [
        sentence[:1000] for sentence in sentences
        if automated_prohibition.search(sentence)
    ]

    limits = []
    per_unit = re.compile(
        r"\b(\d+(?:\.\d+)?)\s*(?:requests?|reqs?)\s*"
        r"(?:per|/)\s*(second|minute|hour)\b",
        re.I,
    )
    shorthand = re.compile(r"\b(\d+(?:\.\d+)?)\s*(rps|rpm|rph)\b", re.I)
    for sentence in sentences:
        for match in per_unit.finditer(sentence):
            value = float(match.group(1))
            unit = match.group(2).lower()
            divisor = {"second": 1, "minute": 60, "hour": 3600}[unit]
            if value > 0:
                limits.append({
                    "requests_per_second": value / divisor,
                    "source_text": sentence[:1000],
                })
        for match in shorthand.finditer(sentence):
            value = float(match.group(1))
            divisor = {"rps": 1, "rpm": 60, "rph": 3600}[match.group(2).lower()]
            if value > 0:
                limits.append({
                    "requests_per_second": value / divisor,
                    "source_text": sentence[:1000],
                })

    strictest = min(
        (item["requests_per_second"] for item in limits),
        default=None,
    )
    minimum_delay = max(0.75, 1.0 / strictest) if strictest else 0.75

    return {
        "active_automated_testing_allowed": not bool(prohibited_sentences),
        "automated_testing_prohibition_evidence": prohibited_sentences,
        "rate_limit_requests_per_second": strictest,
        "minimum_request_delay_seconds": round(minimum_delay, 3),
        "rate_limit_evidence": [item["source_text"] for item in limits[:20]],
        "requires_human_policy_review": True,
        "default_behavior": (
            "Active automated crawling is skipped when an explicit prohibition is detected."
            if prohibited_sentences
            else "Use a conservative 0.75-second delay unless a stricter rate limit is extracted."
        ),
    }


def analyze_program_policy(programme_url, policy_text, source="manual policy text"):
    """Return structured policy interpretation and candidate assets."""
    if not isinstance(policy_text, str) or not policy_text.strip():
        raise ValueError("Policy text is empty.")
    text = policy_text.strip()
    provider = identify_provider(programme_url)
    assets = _extract_assets(text, programme_url)

    included = [item for item in assets if item["disposition"] == "included_candidate"]
    excluded = [item for item in assets if item["disposition"] == "excluded"]
    ambiguous = [item for item in assets if item["disposition"] == "ambiguous"]
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()

    if included and excluded:
        extraction_confidence = "medium"
    else:
        extraction_confidence = "low"

    warnings = [
        "Extracted assets are candidates, not approved scope.",
        "Wildcard hostnames, CIDR ranges, IPs and path-limited URLs are not expanded or automatically authorized.",
        "Exclusions take precedence over conflicting inclusion clues.",
        "Generic policy parsing is used; provider recognition does not imply a provider API adapter.",
        "Policy rules are extracted as review evidence and may require interpretation in their original context.",
    ]
    if not included:
        warnings.append("No clearly included hostname candidates were extracted.")
    if ambiguous:
        warnings.append("Some assets lack clear inclusion or exclusion context.")
    if any(item["type"] in {"url_path", "cidr_network", "ip_address", "wildcard_hostname"}
           for item in assets):
        warnings.append("Non-hostname or broad-scope candidates need separate scope handling and cannot be proposed as ordinary host assets.")

    return {
        "provider": provider,
        "policy": {
            "source": source,
            "fingerprint_sha256": fingerprint,
            "character_count": len(text),
            "extraction_confidence": extraction_confidence,
            "human_review_required": True,
        },
        "scope": {
            "included_candidates": included,
            "excluded_candidates": excluded,
            "ambiguous_candidates": ambiguous,
            "total_candidates": len(assets),
            "approval_performed": False,
        },
        "policy_topics": _extract_topics(text),
        "policy_clues": _extract_policy_clues(text),
        "rules": _extract_rules(text),
        "execution_controls": derive_policy_execution_controls(text),
        "warnings": warnings,
    }
