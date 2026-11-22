"""Authenticated API for remote BugHunter AI desktop clients.

Account creation intentionally remains a terminal-only operation.
"""
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import jwt
from jwt import InvalidTokenError
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.db import SessionLocal, init_db
from app.models.entities import (
    User, Project, ScopeAsset, Finding, FindingReview, Activity,
    ScanCheck, Endpoint, TestCase, Evidence, AssessmentJob, ProgramAsset,
    TestCredentialProfile, ResearcherOwnedResource,
)
from app.services.auth import authenticate
from app.services.projects import (
    create_project,
    add_scope_asset,
    approve_scope,
    delete_project,
    restore_project,
)
from app.services.workflows import (
    add_endpoint,
    initialize_test_plan,
    update_test_case,
)

ISSUER = "bughunter-ai"
TOKEN_MINUTES = 30
bearer = HTTPBearer(auto_error=False)

app = FastAPI(
    title="BugHunter AI API",
    version="1.0.0",
    description="Authenticated, account-isolated BugHunter AI service.",
)


def _secret() -> str:
    value = os.environ.get("BUGHUNTER_API_SECRET", "")
    if len(value) < 32:
        raise RuntimeError(
            "BUGHUNTER_API_SECRET must be set to at least 32 characters."
        )
    return value


def _issue_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    account_id: int
    username: str


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    programme_url: str = Field(default="", max_length=2048)


class ProjectOut(BaseModel):
    id: int
    name: str
    programme_url: str
    description: str
    scope_approved: bool
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AccountOut(BaseModel):
    id: int
    username: str


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid login required.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        payload = jwt.decode(
            credentials.credentials,
            _secret(),
            algorithms=["HS256"],
            issuer=ISSUER,
            options={"require": ["sub", "iss", "iat", "exp"]},
        )
        user_id = int(payload["sub"])
        if user_id <= 0:
            raise ValueError("Invalid account ID.")
    except (InvalidTokenError, ValueError, TypeError, KeyError, RuntimeError):
        raise unauthorized

    user = db.get(User, user_id)
    if user is None:
        raise unauthorized

    # The same request-scoped DB session is used by the route.
    db.info["owner_id"] = user.id
    return user


@app.on_event("startup")
def startup():
    _secret()
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "service": "BugHunter AI API"}


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    username = data.username.strip()
    if not authenticate(db, username, data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    return LoginResponse(
        access_token=_issue_token(user.id),
        expires_in=TOKEN_MINUTES * 60,
        account_id=user.id,
        username=user.username,
    )


@app.get("/api/v1/me", response_model=AccountOut)
def me(user: User = Depends(current_user)):
    return AccountOut(id=user.id, username=user.username)


@app.get("/api/v1/projects", response_model=list[ProjectOut])
def list_projects(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # current_user and this route share the cached request-scoped DB session.
    rows = db.scalars(
        select(Project).order_by(Project.id.desc())
    ).all()
    return rows


@app.post("/api/v1/projects", response_model=ProjectOut, status_code=201)
def add_project(
    data: ProjectCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    programme_url = data.programme_url.strip()
    if programme_url:
        try:
            parsed = urlsplit(programme_url)
            valid = (
                parsed.scheme.lower() == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
            )
            parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(
                status_code=400,
                detail="Programme URL must be a valid HTTPS URL.",
            )

    try:
        project = create_project(db, data.name, programme_url)
        return project
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        db.rollback()
        raise


# Read-only account-scoped project data responses.
class ScopeAssetOut(BaseModel):
    id: int
    project_id: int
    host: str
    included: bool
    approved: bool
    notes: str
    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    project_id: int
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    asset: str
    description: str
    evidence: str
    remediation: str
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingReviewOut(BaseModel):
    id: int
    project_id: int
    finding_id: int
    previous_status: str
    new_status: str
    previous_severity: str
    new_severity: str
    previous_confidence: str
    new_confidence: str
    reviewer: str
    notes: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ActivityOut(BaseModel):
    id: int
    project_id: int
    event: str
    details: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ScanCheckOut(BaseModel):
    id: int
    project_id: int
    asset: str
    check_name: str
    outcome: str
    details: str
    created_at: datetime
    model_config = {"from_attributes": True}


class EndpointOut(BaseModel):
    id: int
    project_id: int
    url: str
    endpoint_type: str
    method: str
    notes: str
    created_at: datetime
    model_config = {"from_attributes": True}


class TestCaseOut(BaseModel):
    id: int
    project_id: int
    category: str
    title: str
    target: str
    status: str
    notes: str
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class EvidenceOut(BaseModel):
    id: int
    project_id: int
    finding_id: int | None
    test_case_id: int | None
    scan_check_id: int | None
    original_name: str
    sha256: str
    size_bytes: int
    content_type: str
    notes: str
    created_at: datetime
    model_config = {"from_attributes": True}


class AssessmentJobOut(BaseModel):
    id: int
    project_id: int
    job_type: str
    status: str
    progress: int
    checkpoint: str
    result_summary: str
    error_message: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    model_config = {"from_attributes": True}


def _require_owned_project(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project


@app.get("/api/v1/projects/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return _require_owned_project(db, project_id)


@app.get("/api/v1/projects/{project_id}/assets",
         response_model=list[ScopeAssetOut])
def get_project_assets(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(ScopeAsset)
        .where(ScopeAsset.project_id == project_id)
        .order_by(ScopeAsset.id)
    ).all()


@app.get("/api/v1/projects/{project_id}/findings",
         response_model=list[FindingOut])
def get_project_findings(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/reviews",
         response_model=list[FindingReviewOut])
def get_project_reviews(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(FindingReview)
        .where(FindingReview.project_id == project_id)
        .order_by(FindingReview.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/activities",
         response_model=list[ActivityOut])
def get_project_activities(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(Activity)
        .where(Activity.project_id == project_id)
        .order_by(Activity.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/checks",
         response_model=list[ScanCheckOut])
def get_project_checks(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(ScanCheck)
        .where(ScanCheck.project_id == project_id)
        .order_by(ScanCheck.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/endpoints",
         response_model=list[EndpointOut])
def get_project_endpoints(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(Endpoint)
        .where(Endpoint.project_id == project_id)
        .order_by(Endpoint.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/test-cases",
         response_model=list[TestCaseOut])
def get_project_test_cases(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(TestCase)
        .where(TestCase.project_id == project_id)
        .order_by(TestCase.id)
    ).all()


@app.get("/api/v1/projects/{project_id}/evidence",
         response_model=list[EvidenceOut])
def get_project_evidence(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(Evidence)
        .where(Evidence.project_id == project_id)
        .order_by(Evidence.id.desc())
    ).all()


@app.get("/api/v1/projects/{project_id}/jobs",
         response_model=list[AssessmentJobOut])
def get_project_jobs(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(AssessmentJob)
        .where(AssessmentJob.project_id == project_id)
        .order_by(AssessmentJob.id.desc())
    ).all()


class HuntCreateRequest(BaseModel):
    start_url: str = Field(min_length=1, max_length=2048)
    max_pages: int = Field(default=100, ge=1, le=100)


@app.post(
    "/api/v1/projects/{project_id}/hunts",
    response_model=AssessmentJobOut,
    status_code=202,
)
def queue_project_hunt(
    project_id: int,
    data: HuntCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    from app.services.jobs import create_hunt_job

    try:
        return create_hunt_job(
            db,
            project_id,
            data.start_url,
            max_pages=data.max_pages,
        )
    except ValueError as exc:
        _service_error(db, exc)


# REMOTE_WRITE_ROUTES_V1
# All operations below require an authenticated, account-scoped DB session.


class ProjectConfirmation(BaseModel):
    confirmation_name: str = Field(min_length=1, max_length=200)


class ScopeAssetCreate(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    included: bool = True
    notes: str = Field(default="", max_length=10000)


class ScopeApprovalRequest(BaseModel):
    policy_text: str = Field(min_length=1, max_length=200000)


class EndpointCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    endpoint_type: str = Field(default="Web page", min_length=1, max_length=80)
    method: str = Field(default="GET", min_length=1, max_length=12)
    notes: str = Field(default="", max_length=20000)


class TestCaseUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    target: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=100000)


class TestCredentialProfileCreate(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    name: str = Field(min_length=1, max_length=120)
    role_label: str = Field(min_length=1, max_length=80)
    auth_type: str = Field(min_length=1, max_length=20)
    # Length and newline validation happen in the vault service so validation
    # errors never echo the submitted credential value back to the client.
    secret: str


class TestCredentialProfileOut(BaseModel):
    id: int
    host: str
    name: str
    role_label: str
    auth_type: str
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ResearcherOwnedResourceCreate(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    endpoint_template: str = Field(min_length=1, max_length=2048)
    owner_profile_id: int = Field(gt=0)
    resource_reference: str = Field(min_length=1, max_length=512)
    attestation_note: str = Field(min_length=20, max_length=2000)


class ResearcherOwnedResourceOut(BaseModel):
    id: int
    host: str
    endpoint_template: str
    owner_profile_id: int
    resource_fingerprint: str
    attestation_note: str
    ownership_attested: bool
    created_at: datetime

    model_config = {"from_attributes": True}



class FindingReviewUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    category: str = Field(min_length=1, max_length=100)
    severity: str = Field(min_length=1, max_length=30)
    confidence: str = Field(min_length=1, max_length=30)
    status: str = Field(min_length=1, max_length=40)
    asset: str = Field(default="", max_length=2048)
    description: str = Field(default="", max_length=100000)
    evidence: str = Field(default="", max_length=100000)
    remediation: str = Field(default="", max_length=100000)
    review_notes: str = Field(default="", max_length=50000)


def _service_error(db: Session, exc: ValueError):
    db.rollback()
    raise HTTPException(status_code=400, detail=str(exc))


@app.post(
    "/api/v1/projects/{project_id}/archive",
    response_model=ProjectOut,
)
def archive_project_api(
    project_id: int,
    data: ProjectConfirmation,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    try:
        return delete_project(db, project_id, data.confirmation_name)
    except ValueError as exc:
        _service_error(db, exc)


@app.post(
    "/api/v1/projects/{project_id}/restore",
    response_model=ProjectOut,
)
def restore_project_api(
    project_id: int,
    data: ProjectConfirmation,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # db.get is account-scoped; the service also verifies archived status.
    _require_owned_project(db, project_id)
    try:
        return restore_project(db, project_id, data.confirmation_name)
    except ValueError as exc:
        _service_error(db, exc)


@app.post(
    "/api/v1/projects/{project_id}/assets",
    response_model=ScopeAssetOut,
    status_code=201,
)
def create_scope_asset_api(
    project_id: int,
    data: ScopeAssetCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    try:
        # The client may choose inclusion, but cannot set approved=True.
        return add_scope_asset(
            db,
            project_id,
            data.host,
            included=data.included,
            notes=data.notes,
        )
    except ValueError as exc:
        _service_error(db, exc)


@app.post(
    "/api/v1/projects/{project_id}/approve-scope",
    response_model=ProjectOut,
)
def approve_project_scope_api(
    project_id: int,
    data: ScopeApprovalRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    project = _require_owned_project(db, project_id)
    try:
        # This is an explicit approval action, never triggered by adding assets.
        project.policy_text = data.policy_text.strip()
        approve_scope(db, project)
        db.refresh(project)
        return project
    except ValueError as exc:
        _service_error(db, exc)


@app.post(
    "/api/v1/projects/{project_id}/endpoints",
    response_model=EndpointOut,
    status_code=201,
)
def create_endpoint_api(
    project_id: int,
    data: EndpointCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)

    method = data.method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise HTTPException(status_code=400, detail="Unsupported HTTP method.")

    try:
        # add_endpoint validates the URL against the explicitly approved scope.
        return add_endpoint(
            db,
            project_id,
            data.url,
            data.endpoint_type.strip(),
            method,
            data.notes,
        )
    except ValueError as exc:
        _service_error(db, exc)


@app.post(
    "/api/v1/projects/{project_id}/initialize-test-plan",
)
def initialize_project_test_plan_api(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    try:
        created = initialize_test_plan(db, project_id)
        return {"created": created, "message": "Test plan initialized."}
    except ValueError as exc:
        _service_error(db, exc)


@app.patch(
    "/api/v1/projects/{project_id}/test-cases/{test_id}",
    response_model=TestCaseOut,
)
def update_project_test_case_api(
    project_id: int,
    test_id: int,
    data: TestCaseUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    test = db.get(TestCase, test_id)
    if test is None or test.project_id != project_id:
        raise HTTPException(status_code=404, detail="Test case not found.")

    target = test.target if data.target is None else data.target
    notes = test.notes if data.notes is None else data.notes

    try:
        update_test_case(
            db,
            project_id,
            test_id,
            data.status,
            target=target,
            notes=notes,
        )
        db.refresh(test)
        return test
    except ValueError as exc:
        _service_error(db, exc)


@app.patch(
    "/api/v1/projects/{project_id}/findings/{finding_id}",
    response_model=FindingOut,
)
def review_project_finding_api(
    project_id: int,
    finding_id: int,
    data: FindingReviewUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    finding = db.get(Finding, finding_id)

    if finding is None or finding.project_id != project_id:
        raise HTTPException(status_code=404, detail="Finding not found.")

    allowed_categories = {
        "Access Control", "Authentication", "Injection", "XSS", "SSRF",
        "Security Misconfiguration", "Information Disclosure",
        "Cryptography", "Business Logic", "API Security", "Other",
    }
    allowed_severities = {"info", "low", "medium", "high", "critical"}
    allowed_confidences = {"low", "medium", "high"}
    allowed_statuses = {
        "potential", "needs_review", "confirmed", "rejected", "resolved",
    }

    if data.category not in allowed_categories:
        raise HTTPException(status_code=400, detail="Invalid finding category.")
    if data.severity not in allowed_severities:
        raise HTTPException(status_code=400, detail="Invalid finding severity.")
    if data.confidence not in allowed_confidences:
        raise HTTPException(status_code=400, detail="Invalid finding confidence.")
    if data.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid finding status.")
    if not data.title.strip():
        raise HTTPException(status_code=400, detail="Finding title is required.")

    previous_status = finding.status
    previous_severity = finding.severity
    previous_confidence = finding.confidence

    try:
        finding.title = data.title.strip()
        finding.category = data.category
        finding.severity = data.severity
        finding.confidence = data.confidence
        finding.status = data.status
        finding.asset = data.asset.strip()
        finding.description = data.description.strip()
        finding.evidence = data.evidence.strip()
        finding.remediation = data.remediation.strip()

        db.add(FindingReview(
            project_id=project_id,
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=finding.status,
            previous_severity=previous_severity,
            new_severity=finding.severity,
            previous_confidence=previous_confidence,
            new_confidence=finding.confidence,
            reviewer=user.username,
            notes=data.review_notes.strip(),
        ))

        # Finding, review history and activity are committed atomically.
        db.add(Activity(
            project_id=project_id,
            event="Finding reviewed",
            details=(
                f"Finding #{finding.id}: {previous_status} -> {finding.status}; "
                f"severity={finding.severity}; confidence={finding.confidence}"
            ),
        ))
        db.commit()
        db.refresh(finding)
        return finding
    except Exception:
        db.rollback()
        raise


# Versioned program policy analysis. This retrieves/analyzes the program page
# or supplied policy text; it does not contact discovered target assets.
class ProgramAnalysisRequest(BaseModel):
    policy_text: str = Field(default="", max_length=200000)


class ProgramAssetReviewRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=40)
    note: str = Field(default="", max_length=10000)


@app.post("/api/v1/projects/{project_id}/analyze-program")
def analyze_project_program(
    project_id: int,
    data: ProgramAnalysisRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from app.services.program_policy_store import analyze_and_store_program

    try:
        return analyze_and_store_program(
            db,
            project_id,
            manual_policy=data.policy_text,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception:
        db.rollback()
        raise


@app.get("/api/v1/projects/{project_id}/program-policies")
def get_project_program_policies(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from app.services.program_policy_store import list_program_policies

    try:
        return list_program_policies(db, project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# Human review of policy-extracted asset candidates.
# Review decisions never approve an asset for testing.
@app.patch(
    "/api/v1/projects/{project_id}/program-assets/{asset_id}/review"
)
def review_program_asset_api(
    project_id: int,
    asset_id: int,
    data: ProgramAssetReviewRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)

    decision = data.decision.strip().lower()
    if decision not in {"accepted", "rejected", "deferred"}:
        raise HTTPException(
            status_code=400,
            detail="Decision must be accepted, rejected, or deferred.",
        )

    asset = db.scalar(
        select(ProgramAsset).where(
            ProgramAsset.id == asset_id,
            ProgramAsset.project_id == project_id,
        )
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Candidate not found.")

    project = _require_owned_project(db, project_id)
    if project.status == "deleted":
        raise HTTPException(
            status_code=409,
            detail="Archived projects are read-only.",
        )

    from datetime import datetime, timezone

    asset.review_status = decision
    asset.review_note = data.note.strip()
    asset.reviewed_at = datetime.now(timezone.utc)
    asset.reviewed_by_user_id = user.id

    db.add(Activity(
        project_id=project_id,
        event="Program asset candidate reviewed",
        details=f"Candidate #{asset.id}: {decision}",
    ))

    db.commit()
    db.refresh(asset)

    return {
        "id": asset.id,
        "asset": asset.asset,
        "disposition": asset.disposition,
        "review_status": asset.review_status,
        "review_note": asset.review_note,
        "reviewed_at": asset.reviewed_at,
        "reviewed_by_user_id": asset.reviewed_by_user_id,
    }


@app.post(
    "/api/v1/projects/{project_id}/program-assets/propose-clear-hostnames",
    status_code=200,
)
def propose_clear_program_hostnames_api(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Bulk-propose only explicit, exact-host inclusion candidates.

    This is not approval. Wildcards, IP ranges, IP literals, URLs and
    ambiguous/low-confidence entries are intentionally excluded.
    """
    project = _require_owned_project(db, project_id)
    if project.status == "deleted":
        raise HTTPException(status_code=409, detail="Archived projects are read-only.")

    from app.models.entities import ProgramPolicy
    latest_policy = db.scalar(
        select(ProgramPolicy)
        .where(ProgramPolicy.project_id == project_id)
        .order_by(ProgramPolicy.version_number.desc())
        .limit(1)
    )
    if latest_policy is None:
        raise HTTPException(status_code=409, detail="Analyze the programme policy first.")

    candidates = db.scalars(
        select(ProgramAsset)
        .where(
            ProgramAsset.project_id == project_id,
            ProgramAsset.policy_id == latest_policy.id,
            ProgramAsset.disposition == "included_candidate",
            ProgramAsset.asset_type == "hostname",
            ProgramAsset.confidence == "medium",
        )
        .order_by(ProgramAsset.id.asc())
    ).all()

    existing = {
        str(item.host).strip().lower().rstrip(".")
        for item in db.scalars(
            select(ScopeAsset).where(ScopeAsset.project_id == project_id)
        ).all()
    }
    proposed = []
    skipped_existing = []
    for candidate in candidates:
        host = candidate.asset.strip().lower().rstrip(".")
        if host in existing:
            skipped_existing.append(host)
            continue
        try:
            asset = add_scope_asset(
                db,
                project_id,
                host,
                included=True,
                notes=(
                    f"Proposed from policy version {latest_policy.version_number}; "
                    f"candidate #{candidate.id}; explicit inclusion wording detected. "
                    "Not authorized until the complete scope is separately approved."
                ),
            )
        except ValueError as exc:
            # Duplicate rows are harmless; invalid values are not proposed.
            if "already registered" in str(exc):
                skipped_existing.append(host)
                continue
            raise HTTPException(status_code=400, detail=str(exc))
        proposed.append({"id": asset.id, "host": asset.host})
        existing.add(host)

    return {
        "policy_version": latest_policy.version_number,
        "proposed_count": len(proposed),
        "skipped_existing_count": len(skipped_existing),
        "proposed": proposed,
        "excluded_candidates_never_proposed": True,
        "broad_or_non_host_assets_never_proposed": True,
        "approved": False,
        "message": (
            "Clear exact-host inclusion candidates were added to proposed scope. "
            "Review the complete list and approve it before any target testing."
        ),
    }


@app.post(
    "/api/v1/projects/{project_id}/program-assets/{asset_id}/add-to-scope",
    status_code=201,
)
def add_program_asset_to_scope_api(
    project_id: int,
    asset_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    project = _require_owned_project(db, project_id)

    if project.status == "deleted":
        raise HTTPException(
            status_code=409,
            detail="Archived projects are read-only.",
        )

    candidate = db.scalar(
        select(ProgramAsset).where(
            ProgramAsset.id == asset_id,
            ProgramAsset.project_id == project_id,
        )
    )
    if candidate is None:
        raise HTTPException(status_code=404, detail="Candidate not found.")

    from app.models.entities import ProgramPolicy
    latest_policy = db.scalar(
        select(ProgramPolicy)
        .where(ProgramPolicy.project_id == project_id)
        .order_by(ProgramPolicy.version_number.desc())
        .limit(1)
    )
    if latest_policy is None or candidate.policy_id != latest_policy.id:
        raise HTTPException(
            status_code=409,
            detail="This candidate belongs to an older policy version. Re-analyze and review the latest policy.",
        )

    if candidate.asset_type not in {"hostname", "ip_address"}:
        raise HTTPException(
            status_code=409,
            detail=(
                "This asset type cannot be converted into a single-host scope entry. "
                "Wildcard, CIDR and URL candidates must remain unapproved until "
                "their exact authorization boundaries can be represented."
            ),
        )

    if candidate.review_status != "accepted":
        raise HTTPException(
            status_code=409,
            detail="Only explicitly accepted candidates can be proposed for scope.",
        )

    if candidate.disposition == "excluded":
        raise HTTPException(
            status_code=409,
            detail="A policy-excluded asset cannot be added to proposed scope.",
        )

    try:
        scope_asset = add_scope_asset(
            db,
            project_id,
            candidate.asset,
            included=True,
            notes=(
                f"Proposed from policy version candidate #{candidate.id}. "
                "Human review accepted; authorization still requires separate scope approval."
            ),
        )
    except ValueError as exc:
        _service_error(db, exc)

    return {
        "id": scope_asset.id,
        "project_id": scope_asset.project_id,
        "host": scope_asset.host,
        "included": scope_asset.included,
        "approved": scope_asset.approved,
        "notes": scope_asset.notes,
        "message": "Added to proposed scope only. This asset is NOT approved for testing.",
    }


@app.get(
    "/api/v1/projects/{project_id}/test-credentials",
    response_model=list[TestCredentialProfileOut],
)
def get_test_credential_profiles_api(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    from app.services.credential_vault import list_test_credential_profiles
    return list_test_credential_profiles(db, project_id)


@app.post(
    "/api/v1/projects/{project_id}/test-credentials",
    response_model=TestCredentialProfileOut,
    status_code=201,
)
def create_test_credential_profile_api(
    project_id: int,
    data: TestCredentialProfileCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    from app.services.credential_vault import create_test_credential_profile
    try:
        return create_test_credential_profile(
            db,
            project_id,
            data.host,
            data.name,
            data.role_label,
            data.auth_type,
            data.secret,
        )
    except ValueError as exc:
        _service_error(db, exc)
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc


@app.delete(
    "/api/v1/projects/{project_id}/test-credentials/{profile_id}",
    status_code=204,
)
def delete_test_credential_profile_api(
    project_id: int,
    profile_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    from app.services.credential_vault import delete_test_credential_profile
    try:
        delete_test_credential_profile(db, project_id, profile_id)
    except ValueError as exc:
        _service_error(db, exc)


@app.get(
    "/api/v1/projects/{project_id}/owned-resources",
    response_model=list[ResearcherOwnedResourceOut],
)
def list_researcher_owned_resources_api(
    project_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    return db.scalars(
        select(ResearcherOwnedResource)
        .where(ResearcherOwnedResource.project_id == project_id)
        .order_by(ResearcherOwnedResource.id.asc())
    ).all()


@app.post(
    "/api/v1/projects/{project_id}/owned-resources",
    response_model=ResearcherOwnedResourceOut,
    status_code=201,
)
def create_researcher_owned_resource_api(
    project_id: int,
    data: ResearcherOwnedResourceCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    from app.services.owned_resource_registry import (
        register_researcher_owned_resource,
    )
    try:
        return register_researcher_owned_resource(
            db=db,
            project_id=project_id,
            host=data.host,
            endpoint_template=data.endpoint_template,
            owner_profile_id=data.owner_profile_id,
            resource_reference=data.resource_reference,
            attestation_note=data.attestation_note,
        )
    except ValueError as exc:
        _service_error(db, exc)
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.delete(
    "/api/v1/projects/{project_id}/owned-resources/{resource_id}",
    status_code=204,
)
def delete_researcher_owned_resource_api(
    project_id: int,
    resource_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _require_owned_project(db, project_id)
    resource = db.scalar(
        select(ResearcherOwnedResource).where(
            ResearcherOwnedResource.id == resource_id,
            ResearcherOwnedResource.project_id == project_id,
        )
    )
    if resource is None:
        raise HTTPException(status_code=404, detail="Owned resource not found.")
    db.delete(resource)
    db.commit()
