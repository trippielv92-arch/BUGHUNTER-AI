"""Provider-aware, conservative bug bounty program policy intelligence.

This module extracts review candidates only. It never authorizes assets,
approves scope, or initiates target testing.
"""

import hashlib
import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9_-])"
    r"(\*\.)?"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})"
    r"(?![a-z0-9_-])"
)

PROVIDERS = {
    "hackerone": {
        "domains": ("hackerone.com",),
        "name": "HackerOne",
    },
    "bugcrowd": {
        "domains": ("bugcrowd.com",),
        "name": "Bugcrowd",
    },
    "intigriti": {
        "domains": ("intigriti.com",),
        "name": "Intigriti",
    },
    "yeswehack": {
        "domains": ("yeswehack.com",),
        "name": "YesWeHack",
    },
    "immunefi": {
        "domains": ("immunefi.com",),
        "name": "Immunefi",
    },
    "federacy": {
        "domains": ("federacy.com",),
        "name": "Federacy",
    },
}

EXCLUDED_PATTERNS = (
    r"\bout\s+of\s+scope\b",
    r"\bexcluded?\b",
    r"\bnot\s+in\s+scope\b",
    r"\bprohibited\s+assets?\b",
    r"\bdo\s+not\s+test\b",
    r"\bnot\s+eligible\b",
    r"\bexplicitly\s+excluded\b",
)

INCLUDED_PATTERNS = (
    r"\bin\s+scope\b",
    r"\bincluded\s+assets?\b",
    r"\beligible\s+assets?\b",
    r"\btargets?\s+in\s+scope\b",
    r"\bassets?\s+covered\s+by\s+this\s+program\b",
)

POLICY_TOPICS = {
    "testing_restrictions": (
        "rate limit", "denial of service", "automated scanner",
        "social engineering", "destructive", "brute force",
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


def identify_provider(programme_url):
    """Identify a known platform from the program URL hostname."""
    host = (urlparse(programme_url).hostname or "").lower().rstrip(".")

    for provider_id, details in PROVIDERS.items():
        if any(
            host == domain or host.endswith("." + domain)
            for domain in details["domains"]
        ):
            return {
                "id": provider_id,
                "name": details["name"],
                "confidence": "high",
                # Provider recognition exists; API adapters are not implemented yet.
                "adapter_available": False,
            }

    return {
        "id": "unknown",
        "name": "Unknown / direct program",
        "confidence": "low",
        "adapter_available": False,
    }


def _classify_context(context):
    """Only classify assets when nearby policy wording is explicit."""
    text = context.lower()

    if any(re.search(pattern, text) for pattern in EXCLUDED_PATTERNS):
        return "excluded", "medium"

    if any(re.search(pattern, text) for pattern in INCLUDED_PATTERNS):
        return "included_candidate", "medium"

    return "ambiguous", "low"


def _extract_assets(policy_text, programme_url):
    lines = policy_text.splitlines()
    occurrences = {}

    provider_host = (
        urlparse(programme_url).hostname or ""
    ).lower().rstrip(".")

    for index, line in enumerate(lines):
        matches = list(DOMAIN_RE.finditer(line))

        for match in matches:
            wildcard = bool(match.group(1))
            hostname = match.group(2).lower().rstrip(".")

            if hostname == provider_host:
                continue

            # Include nearby lines because policy tables and lists often
            # place the scope label immediately before or after an asset.
            context_start = max(0, index - 1)
            context_end = min(len(lines), index + 2)
            context = "\n".join(lines[context_start:context_end]).strip()

            disposition, confidence = _classify_context(context)
            asset = ("*." if wildcard else "") + hostname

            record = occurrences.setdefault(
                asset,
                {
                    "asset": asset,
                    "type": "wildcard_hostname" if wildcard else "hostname",
                    "disposition": disposition,
                    "confidence": confidence,
                    "evidence": [],
                },
            )

            # A clear exclusion takes precedence over an inclusion clue.
            if disposition == "excluded":
                record["disposition"] = "excluded"
                record["confidence"] = confidence
            elif (
                disposition == "included_candidate"
                and record["disposition"] != "excluded"
            ):
                record["disposition"] = "included_candidate"
                record["confidence"] = confidence

            if context and context not in record["evidence"]:
                record["evidence"].append(context[:600])

    return sorted(
        occurrences.values(),
        key=lambda item: (
            item["disposition"],
            item["asset"],
        ),
    )


def _extract_topics(policy_text):
    lowered = policy_text.lower()
    result = {}

    for topic, phrases in POLICY_TOPICS.items():
        matches = [
            phrase for phrase in phrases
            if phrase in lowered
        ]
        if matches:
            result[topic] = matches

    return result


def _extract_policy_clues(policy_text):
    keys = [
        "rate limit",
        "automated scanner",
        "denial of service",
        "social engineering",
        "out of scope",
        "in scope",
        "authentication",
        "disclosure",
        "safe harbor",
        "test account",
    ]

    clues = {}
    for key in keys:
        found = list(re.finditer(re.escape(key), policy_text, re.I))
        if found:
            clues[key] = [
                policy_text[max(0, match.start() - 100):
                            min(len(policy_text), match.end() + 180)]
                for match in found[:5]
            ]

    return clues


def analyze_program_policy(programme_url, policy_text, source="manual policy text"):
    """Build a conservative structured interpretation of supplied policy text."""
    if not isinstance(policy_text, str) or not policy_text.strip():
        raise ValueError("Policy text is empty.")

    text = policy_text.strip()
    provider = identify_provider(programme_url)
    assets = _extract_assets(text, programme_url)

    included = [
        item for item in assets
        if item["disposition"] == "included_candidate"
    ]
    excluded = [
        item for item in assets
        if item["disposition"] == "excluded"
    ]
    ambiguous = [
        item for item in assets
        if item["disposition"] == "ambiguous"
    ]

    fingerprint = hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()

    if included and excluded:
        extraction_confidence = "medium"
    elif included:
        extraction_confidence = "low"
    else:
        extraction_confidence = "low"

    warnings = [
        "Extracted assets are candidates, not approved scope.",
        "Wildcard hostnames are preserved and are not expanded.",
        "Exclusions must be reviewed before any scope approval.",
        "Provider identification does not prove that the policy was retrieved from an official API.",
    ]

    if not included:
        warnings.append(
            "No clearly labeled included assets were extracted. "
            "Review the official policy and add exact assets manually."
        )

    if ambiguous:
        warnings.append(
            "Some hostnames lack clear inclusion or exclusion context."
        )

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
        "warnings": warnings,
    }
