import ipaddress
import re
from urllib.parse import urlsplit

from sqlalchemy import select
from app.models.entities import Project, ScopeAsset, Activity, AssessmentJob


def log_activity(db, pid, event, details=""):
    db.add(Activity(project_id=pid, event=event, details=details))
    db.commit()


def require_active_project(db, project_id):
    project = db.get(Project, project_id)

    if not project:
        raise ValueError("Project not found.")

    if project.status == "deleted":
        raise ValueError(
            "This project is archived and is read-only."
        )

    return project


def create_project(db, name, url=""):
    owner_id = db.info.get("owner_id")
    if not isinstance(owner_id, int) or owner_id <= 0:
        raise ValueError("Log in with an account before creating a project.")

    if not name.strip():
        raise ValueError("Project name required.")

    p = Project(
        owner_id=owner_id,
        name=name.strip(),
        programme_url=url.strip()
    )
    db.add(p)
    db.commit()
    db.refresh(p)

    log_activity(db, p.id, "Project created")
    return p


def _normalize_scope_asset_host(host):
    """Normalize a hostname or IP address without accepting URL paths."""
    if not isinstance(host, str):
        raise ValueError("Enter a hostname or IP address only.")

    host = host.strip().lower().rstrip(".")

    if (
        not host
        or len(host) > 253
        or any(char.isspace() or ord(char) < 32 for char in host)
        or "/" in host
        or "://" in host
        or "@" in host
    ):
        raise ValueError("Enter a valid hostname or IP address only.")

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc

    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid target hostname.")

    return host


def add_scope_asset(db, pid, host, included=True, notes=""):
    project = require_active_project(db, pid)
    host = _normalize_scope_asset_host(host)

    existing_assets = db.scalars(
        select(ScopeAsset).where(ScopeAsset.project_id == pid)
    ).all()

    for existing in existing_assets:
        try:
            if _normalize_scope_asset_host(existing.host) == host:
                raise ValueError(
                    f"{host} is already registered in this project."
                )
        except ValueError as exc:
            if str(exc).endswith("already registered in this project."):
                raise
            continue

    approval_revoked = bool(project.scope_approved)

    if approval_revoked:
        project.scope_approved = False
        project.status = "draft"

        # A changed scope invalidates every previous asset approval.
        for existing in existing_assets:
            existing.approved = False

    asset = ScopeAsset(
        project_id=pid,
        host=host,
        included=bool(included),
        approved=False,
        notes=notes or "",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    event = "Scope asset added"
    details = host

    if approval_revoked:
        event = "Scope changed; previous approval revoked"
        details = (
            f"Added {host}. All previous asset approvals were revoked; "
            "the complete scope must be reviewed again."
        )

    log_activity(db, pid, event, details)
    return asset


def approve_scope(db, project):
    """Approve only a documented, reviewed set of explicitly included assets."""
    project = require_active_project(db, project.id)

    programme_url = (project.programme_url or "").strip()
    policy_text = (project.policy_text or "").strip()

    if not programme_url:
        raise ValueError(
            "Record the official programme URL before approving scope."
        )

    if len(programme_url) > 2048:
        raise ValueError("The programme URL is too long.")

    try:
        parsed = urlsplit(programme_url)
        valid_programme_url = (
            parsed.scheme.lower() == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
        parsed.port  # Validate malformed or out-of-range ports.
    except ValueError as exc:
        raise ValueError("Enter a valid HTTPS programme URL.") from exc

    if not valid_programme_url:
        raise ValueError(
            "The official programme URL must be a valid HTTPS URL "
            "without embedded credentials."
        )

    if not policy_text:
        raise ValueError(
            "Save the official programme policy text before approving scope."
        )

    assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project.id,
            ScopeAsset.included.is_(True),
        ).order_by(ScopeAsset.host.asc())
    ).all()

    if not assets:
        raise ValueError("Add at least one included asset.")

    normalized_hosts = set()

    for asset in assets:
        normalized = _normalize_scope_asset_host(asset.host)
        if normalized in normalized_hosts:
            raise ValueError(
                f"Duplicate included hostname: {normalized}"
            )
        normalized_hosts.add(normalized)
        asset.host = normalized
        asset.approved = True

    # Excluded assets must never remain approved.
    excluded_assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project.id,
            ScopeAsset.included.is_(False),
        )
    ).all()

    for asset in excluded_assets:
        asset.approved = False

    project.policy_text = policy_text
    project.scope_approved = True
    project.status = "ready"
    db.commit()

    log_activity(
        db,
        project.id,
        "Scope approved",
        "Official programme URL: "
        + programme_url
        + "\\nIncluded approved hosts: "
        + ", ".join(sorted(normalized_hosts)),
    )


def restore_project(db, project_id, confirmation_name):
    """
    Restore an archived project as an unapproved draft.

    Historical findings, evidence and activity records are retained.
    All previous scope approvals are revoked.
    """
    project = db.get(Project, project_id)

    if not project or project.status != "deleted":
        raise ValueError("Archived project not found.")

    if not isinstance(confirmation_name, str):
        raise ValueError("Project name confirmation is required.")

    if confirmation_name.strip() != project.name:
        raise ValueError("Project name confirmation does not match.")

    assets = db.scalars(
        select(ScopeAsset).where(
            ScopeAsset.project_id == project.id
        )
    ).all()

    for asset in assets:
        asset.approved = False

    project.scope_approved = False
    project.status = "draft"

    db.add(Activity(
        project_id=project.id,
        event="Project restored",
        details=(
            "Project restored as draft. "
            "Previous scope approvals revoked. "
            "Fresh scope review and approval required."
        )
    ))

    db.commit()
    db.refresh(project)
    return project


def delete_project(db, project_id, confirmation_name):
    """
    Safely retire a project without destroying audit history,
    findings, evidence records, or evidence files.

    The project is hidden from the active project list.
    """

    project = db.get(Project, project_id)

    if not project:
        raise ValueError("Project does not exist.")

    if project.status == "deleted":
        raise ValueError("Project has already been deleted.")

    active_job = db.scalar(
        select(AssessmentJob.id).where(
            AssessmentJob.project_id == project_id,
            AssessmentJob.status.in_(("queued", "running"))
        ).limit(1)
    )

    if active_job is not None:
        raise ValueError(
            "Cannot retire this project while an assessment job is "
            "queued or running. Stop or finish the job first."
        )

    if confirmation_name.strip() != project.name:
        raise ValueError("Project name confirmation does not match.")

    previous_status = project.status

    project.status = "deleted"
    project.scope_approved = False

    db.add(Activity(
        project_id=project.id,
        event="Project deleted",
        details=(
            f"Project {project.name!r} retired. "
            f"Previous status: {previous_status}. "
            "Related records and evidence retained."
        )
    ))

    db.commit()
    return project
