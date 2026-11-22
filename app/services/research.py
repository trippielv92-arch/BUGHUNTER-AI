from urllib.parse import urlparse
import httpx
from sqlalchemy import select
from app.models.entities import ScopeAsset,ScanCheck,Project,Finding
from app.core.config import REQUEST_TIMEOUT,USER_AGENT
from app.services.projects import log_activity, require_active_project
from app.services.safe_transport import PinnedHTTPTransport
SAFE_HEADERS=["strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy"]
def host_is_approved(host, assets):
    host = (host or "").lower().rstrip(".")
    return any(
        a.approved and a.included
        and host == a.host.lower().rstrip(".")
        for a in assets
    )


def run_safe_assessment(db, pid):
    p = require_active_project(db, pid)

    if not p.scope_approved:
        raise ValueError("Project scope is not approved.")

    assets = db.scalars(
        select(ScopeAsset).where(ScopeAsset.project_id == pid)
    ).all()

    approved = [
        a for a in assets
        if a.approved and a.included
    ]

    if not approved:
        raise ValueError("No approved assets.")

    log_activity(
        db, pid, "Safe assessment started",
        "DNS-pinned HTTPS GET and response-header review per approved host."
    )

    for asset in approved:
        host = asset.host.lower().rstrip(".")
        url = "https://" + host + "/"

        try:
            if not host_is_approved(host, assets):
                raise ValueError("Host is not an exactly approved asset.")

            transport = PinnedHTTPTransport(host)
            transport.validate_dns()

            with httpx.Client(
                transport=transport,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                # Stream only the response headers. The assessment does not
                # need to download or retain the response body.
                with client.stream("GET", url) as response:
                    missing = [
                        header for header in SAFE_HEADERS
                        if header not in response.headers
                    ]
                    detail = (
                        f"HTTP {response.status_code}; "
                        "missing headers: "
                        f"{', '.join(missing) if missing else 'none'}"
                    )

                    db.add(ScanCheck(
                        project_id=pid,
                        asset=url,
                        check_name="HTTPS security headers",
                        outcome="completed",
                        details=detail,
                    ))

                    if missing:
                        db.add(Finding(
                            project_id=pid,
                            title="Potential missing security headers",
                            category="Security Misconfiguration",
                            severity="low",
                            confidence="low",
                            status="potential",
                            asset=url,
                            description=(
                                "Commonly recommended response headers were "
                                "absent. This is not proof of an exploitable "
                                "vulnerability."
                            ),
                            evidence=detail,
                            remediation=(
                                "Review and configure response headers "
                                "appropriate to the application."
                            ),
                        ))

            db.commit()

        except Exception as exc:
            db.rollback()
            db.add(ScanCheck(
                project_id=pid,
                asset=url,
                check_name="HTTPS security headers",
                outcome="failed",
                details=f"{type(exc).__name__}: {str(exc)[:700]}",
            ))
            db.commit()

    log_activity(
        db, pid, "Safe assessment completed",
        f"{len(approved)} approved host(s)"
    )
