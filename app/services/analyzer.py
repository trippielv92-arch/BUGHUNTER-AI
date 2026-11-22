"""Safe public program URL retrieval and conservative policy analysis."""

import ipaddress
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.config import REQUEST_TIMEOUT, USER_AGENT
from app.services.program_intelligence import analyze_program_policy
from app.services.safe_transport import PinnedHTTPTransport


MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}


def validate_programme_url(url):
    """Normalize a public HTTPS programme URL without resolving its hostname."""
    parsed = urlparse((url or "").strip())

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Programme URL contains an invalid port.") from exc

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in (None, 443)
    ):
        raise ValueError(
            "Programme URL must use HTTPS on port 443, "
            "with a hostname and without embedded credentials."
        )

    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname:
        raise ValueError("Programme URL hostname is empty.")

    # Canonicalize IP literals and convert internationalized DNS names
    # to ASCII IDNA form before constructing the request URL.
    try:
        ip = ipaddress.ip_address(hostname)
        normalized_host = ip.compressed
        authority = (
            f"[{normalized_host}]" if ip.version == 6 else normalized_host
        )
    except ValueError:
        try:
            normalized_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Programme URL hostname is invalid.") from exc
        authority = normalized_host

    return parsed._replace(
        netloc=authority,
        fragment="",
    ).geturl()


def _validate_public_destination(url):
    """Validate URL shape; DNS/IP validation happens in the pinned transport."""
    return validate_programme_url(url)


def _retrieve_public_page(url):
    """Fetch bounded HTML using a separately DNS-pinned transport per host."""
    current_url = _validate_public_destination(url)

    for redirect_number in range(MAX_REDIRECTS + 1):
        current_url = _validate_public_destination(current_url)
        hostname = urlparse(current_url).hostname

        # Every redirect destination gets its own pinned connection pool.
        transport = PinnedHTTPTransport(hostname)
        try:
            transport.validate_dns()

            with httpx.Client(
                transport=transport,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
            ) as client:
                with client.stream("GET", current_url) as response:
                    if response.status_code in REDIRECT_CODES:
                        location = response.headers.get("location")
                        if not location:
                            raise ValueError(
                                "Redirect response has no Location header."
                            )
                        if redirect_number >= MAX_REDIRECTS:
                            raise ValueError(
                                "Programme page exceeded the redirect limit."
                            )

                        # The next iteration validates and pins this destination.
                        current_url = urljoin(current_url, location)
                        continue

                    if 300 <= response.status_code < 400:
                        raise ValueError(
                            "Unsupported programme-page redirect."
                        )

                    response.raise_for_status()

                    chunks = []
                    total = 0
                    for chunk in response.iter_bytes():
                        if not chunk:
                            continue

                        remaining = MAX_POLICY_BYTES - total
                        if remaining <= 0:
                            break

                        part = chunk[:remaining]
                        chunks.append(part)
                        total += len(part)

                        if len(part) < len(chunk) or total >= MAX_POLICY_BYTES:
                            break

                    raw = b"".join(chunks)
                    encoding = response.encoding or "utf-8"
                    return raw.decode(encoding, errors="replace")
        finally:
            transport.close()

    raise ValueError("Programme page could not be retrieved.")


def analyze_programme(url, manual_policy=""):
    """Analyze a public program page or manually supplied policy text.

    This function does not approve assets or contact discovered target assets.
    """
    url = validate_programme_url(url)
    text = (manual_policy or "").strip()
    title = ""
    source = "manual policy text"

    if not text:
        try:
            html = _retrieve_public_page(url)
            soup = BeautifulSoup(html, "html.parser")
            title = (
                soup.title.get_text(" ", strip=True)
                if soup.title else ""
            )

            for node in soup(["script", "style", "noscript"]):
                node.decompose()

            text = soup.get_text("\n", strip=True)[:200000]
            if not text:
                raise ValueError("The retrieved page contained no readable policy text.")
            source = "public webpage"

        except Exception as exc:
            raise RuntimeError(
                "Program page retrieval failed. Paste the official policy "
                "text manually instead. "
                f"({type(exc).__name__}: {exc})"
            ) from exc

    intelligence = analyze_program_policy(
        url,
        text,
        source=source,
    )

    all_candidates = (
        intelligence["scope"]["included_candidates"]
        + intelligence["scope"]["excluded_candidates"]
        + intelligence["scope"]["ambiguous_candidates"]
    )

    candidate_domains = sorted({
        item["asset"] for item in all_candidates
    })

    return {
        "url": url,
        "title": title,
        "source": source,
        "policy_text": text,
        "candidate_domains": candidate_domains,
        "policy_clues": intelligence["policy_clues"],
        "warning": (
            "Extraction is advisory. Independently verify the official "
            "program rules. No assets are approved automatically."
        ),
        "provider": intelligence["provider"],
        "policy": intelligence["policy"],
        "scope": intelligence["scope"],
        "policy_topics": intelligence["policy_topics"],
        "rules": intelligence["rules"],
        "execution_controls": intelligence["execution_controls"],
        "warnings": intelligence["warnings"],
    }
