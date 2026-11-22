"""Passive reconnaissance: local DNS and public Certificate Transparency only.

Discovered hostnames are always stored as unapproved candidates.
No discovered hostname is contacted or actively tested.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.models.entities import Project, ScopeAsset, ScanCheck, Activity
from app.services.safe_transport import PinnedHTTPTransport


HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
MAX_CT_RESPONSE_BYTES = 2_000_000
MAX_CANDIDATES_PER_ASSET = 500


def _valid_hostname(value: str) -> str | None:
    host = (value or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or not HOST_RE.fullmatch(host):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def _public_addresses(host: str) -> list[str]:
    """Resolve locally; never send an HTTP request to the hostname."""
    found = set()
    try:
        records = socket.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        for record in records:
            try:
                address = ipaddress.ip_address(record[4][0])
                if address.is_global:
                    found.add(str(address))
            except ValueError:
                continue
    except (socket.gaierror, OSError):
        pass
    return sorted(found)


def _record(db, project_id: int, host: str, name: str,
            outcome: str, details: str) -> None:
    db.add(ScanCheck(
        project_id=project_id,
        asset=host,
        check_name=name,
        outcome=outcome,
        details=details[:12000],
    ))


def _activity(db, project_id: int, event: str, details: str) -> None:
    db.add(Activity(
        project_id=project_id,
        event=event,
        details=details[:12000],
    ))


def _approved_hosts(project: Project) -> list[str]:
    hosts = []
    for asset in project.assets:
        if not asset.included or not asset.approved:
            continue
        host = _valid_hostname(asset.host)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _ct_names(client: httpx.Client, host: str) -> tuple[set[str], str]:
    """Query crt.sh with a strict streaming response-size limit."""
    names: set[str] = set()
    queries = (host, f"%.{host}")

    for query in queries:
        try:
            with client.stream(
                "GET",
                "https://crt.sh/",
                params={"q": query, "output": "json"},
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    return names, (
                        f"Certificate Transparency returned HTTP "
                        f"{response.status_code}"
                    )

                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > MAX_CT_RESPONSE_BYTES:
                            return names, (
                                "Certificate Transparency response exceeded "
                                "2 MB; download stopped."
                            )
                    except ValueError:
                        pass

                chunks = []
                total = 0

                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    if not chunk:
                        continue

                    if total + len(chunk) > MAX_CT_RESPONSE_BYTES:
                        return names, (
                            "Certificate Transparency response exceeded "
                            "2 MB; download stopped."
                        )

                    chunks.append(chunk)
                    total += len(chunk)

                body = b"".join(chunks)

            records = json.loads(body.decode("utf-8"))

            if not isinstance(records, list):
                return names, (
                    "Certificate Transparency returned an unexpected response"
                )

            for record in records:
                if not isinstance(record, dict):
                    continue

                raw = record.get("name_value", "")
                if not isinstance(raw, str):
                    continue

                for line in raw.splitlines():
                    candidate = _valid_hostname(line)

                    if candidate and (
                        candidate == host
                        or candidate.endswith("." + host)
                    ):
                        names.add(candidate)

                    if len(names) >= MAX_CANDIDATES_PER_ASSET:
                        return names, "Candidate limit reached"

        except (httpx.HTTPError, ValueError, TypeError) as exc:
            return names, (
                f"Certificate Transparency lookup failed: "
                f"{type(exc).__name__}: {exc}"
            )

    return names, (
        f"Certificate Transparency returned {len(names)} unique matching names"
    )

def run_passive_recon(
    db,
    project_id: int,
    *,
    use_certificate_transparency: bool = True,
    delay_seconds: float = 1.0,
    progress_callback=None,
    stop_event: threading.Event | None = None,
) -> dict:
    """Discover DNS and CT data for explicitly approved project assets."""
    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found.")
    if not project.scope_approved:
        raise ValueError("Project scope must be approved in the application first.")

    approved = _approved_hosts(project)
    if not approved:
        raise ValueError("No included and approved host assets are registered.")

    existing = {
        (asset.host or "").strip().lower().rstrip(".")
        for asset in db.scalars(
            select(ScopeAsset).where(ScopeAsset.project_id == project_id)
        ).all()
    }

    result = {
        "project_id": project_id,
        "approved_assets": approved,
        "dns": {},
        "certificate_names": [],
        "new_candidates": [],
        "errors": [],
        "requests_to_target_hosts": 0,
        "ct_requests": 0,
        "stopped": False,
        "completed_at": None,
        "notice": (
            "Passive discovery only. Candidates are not authorized for active "
            "testing until manually reviewed against programme policy."
        ),
    }

    timeout = httpx.Timeout(12.0, connect=5.0)
    delay = max(0.0, min(float(delay_seconds), 10.0))

    # CT is optional: a CT DNS/setup failure must not prevent local DNS discovery.
    ct_available = bool(use_certificate_transparency)
    ct_setup_error = None

    if ct_available:
        try:
            ct_transport = PinnedHTTPTransport("crt.sh")
            ct_transport.validate_dns()
        except Exception as exc:
            ct_available = False
            ct_setup_error = (
                f"Certificate Transparency transport unavailable: "
                f"{type(exc).__name__}: {str(exc)[:300]}"
            )
            result["errors"].append(ct_setup_error)
            ct_transport = httpx.MockTransport(
                lambda request: httpx.Response(503)
            )
    else:
        # CT-disabled runs must not resolve or contact external services.
        ct_transport = httpx.MockTransport(
            lambda request: httpx.Response(503)
        )

    with httpx.Client(
        transport=ct_transport,
        timeout=timeout,
        headers={"User-Agent": "BugHunter-AI-Passive-Recon/1.1"},
        trust_env=False,
    ) as client:
        for index, host in enumerate(approved):
            if stop_event is not None and stop_event.is_set():
                result["stopped"] = True
                break

            addresses = _public_addresses(host)
            result["dns"][host] = {
                "public_addresses": addresses,
                "resolution": "resolved" if addresses else "no_public_address_returned",
            }
            _record(
                db, project_id, host, "DNS resolution",
                "completed" if addresses else "no_result",
                json.dumps(result["dns"][host]),
            )

            if use_certificate_transparency:
                if not ct_available:
                    # Record the CT outage, but preserve this host's DNS result.
                    _record(
                        db, project_id, host, "Certificate Transparency",
                        "failed",
                        ct_setup_error or "Certificate Transparency is unavailable.",
                    )
                else:
                    if index and delay and stop_event is not None:
                        if stop_event.wait(delay):
                            result["stopped"] = True
                            break
                    elif index and delay:
                        time.sleep(delay)

                    if stop_event is not None and stop_event.is_set():
                        result["stopped"] = True
                        break

                    result["ct_requests"] += 2
                    names, message = _ct_names(client, host)
                    result["certificate_names"] = sorted(
                        set(result["certificate_names"]) | names
                    )
                    _record(
                        db, project_id, host, "Certificate Transparency",
                        "completed" if names else "no_result",
                        message + "; names=" + json.dumps(sorted(names)[:500]),
                    )

                    if "failed" in message.lower() or "returned HTTP" in message:
                        result["errors"].append(f"{host}: {message}")

                    for candidate in sorted(names):
                        if candidate == host or candidate in existing:
                            continue
                        if not candidate.endswith("." + host):
                            continue

                        db.add(ScopeAsset(
                            project_id=project_id,
                            host=candidate,
                            included=False,
                            approved=False,
                            notes=(
                                "Discovered through Certificate Transparency. "
                                "UNREVIEWED: verify programme policy and explicitly "
                                "approve before any active testing."
                            ),
                        ))
                        existing.add(candidate)
                        result["new_candidates"].append(candidate)

            # Commit each asset's work so an interrupted run retains its audit trail.
            db.commit()

            percent = int(((index + 1) / len(approved)) * 100)
            message = f"Processed {index + 1}/{len(approved)} approved assets: {host}"
            if progress_callback:
                progress_callback(percent, message)

    result["certificate_names"] = sorted(set(result["certificate_names"]))
    result["new_candidates"] = sorted(set(result["new_candidates"]))
    result["completed_at"] = datetime.now(timezone.utc).isoformat()

    event = (
        "Passive reconnaissance stopped"
        if result["stopped"]
        else "Passive reconnaissance completed"
    )
    _activity(
        db,
        project_id,
        event,
        (
            f"Approved assets: {len(approved)}; CT requests: {result['ct_requests']}; "
            f"candidate names: {len(result['certificate_names'])}; "
            f"new unapproved candidates: {len(result['new_candidates'])}. "
            "No discovered hosts were probed."
        ),
    )
    db.commit()
    return result
