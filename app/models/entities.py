from datetime import datetime, timezone
from sqlalchemy import String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.db import Base
def now_utc(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__="users"
    id: Mapped[int]=mapped_column(primary_key=True)
    username: Mapped[str]=mapped_column(String(120), unique=True)
    password_hash: Mapped[str]=mapped_column(String(512))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now_utc)
class Project(Base):
    __tablename__="projects"
    id: Mapped[int]=mapped_column(primary_key=True)
    owner_id: Mapped[int | None]=mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str]=mapped_column(String(200))
    programme_url: Mapped[str]=mapped_column(String(2048),default="")
    description: Mapped[str]=mapped_column(Text,default="")
    policy_text: Mapped[str]=mapped_column(Text,default="")
    scope_approved: Mapped[bool]=mapped_column(Boolean,default=False)
    status: Mapped[str]=mapped_column(String(40),default="draft")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now_utc)
    assets: Mapped[list["ScopeAsset"]]=relationship(back_populates="project",cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]]=relationship(back_populates="project",cascade="all, delete-orphan")
class ScopeAsset(Base):
    __tablename__="scope_assets"
    id: Mapped[int]=mapped_column(primary_key=True)
    project_id: Mapped[int]=mapped_column(ForeignKey("projects.id"))
    host: Mapped[str]=mapped_column(String(255))
    included: Mapped[bool]=mapped_column(Boolean,default=True)
    approved: Mapped[bool]=mapped_column(Boolean,default=False)
    notes: Mapped[str]=mapped_column(Text,default="")
    project: Mapped[Project]=relationship(back_populates="assets")
class Finding(Base):
    __tablename__="findings"
    id: Mapped[int]=mapped_column(primary_key=True)
    project_id: Mapped[int]=mapped_column(ForeignKey("projects.id"))
    title: Mapped[str]=mapped_column(String(300))
    category: Mapped[str]=mapped_column(String(100),default="Informational")
    severity: Mapped[str]=mapped_column(String(30),default="info")
    confidence: Mapped[str]=mapped_column(String(30),default="low")
    status: Mapped[str]=mapped_column(String(40),default="potential")
    asset: Mapped[str]=mapped_column(String(2048),default="")
    description: Mapped[str]=mapped_column(Text,default="")
    evidence: Mapped[str]=mapped_column(Text,default="")
    remediation: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now_utc)
    project: Mapped[Project]=relationship(back_populates="findings")
class FindingReview(Base):
    __tablename__ = "finding_reviews"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id"), index=True
    )
    previous_status: Mapped[str] = mapped_column(String(40), default="")
    new_status: Mapped[str] = mapped_column(String(40), default="")
    previous_severity: Mapped[str] = mapped_column(String(30), default="")
    new_severity: Mapped[str] = mapped_column(String(30), default="")
    previous_confidence: Mapped[str] = mapped_column(String(30), default="")
    new_confidence: Mapped[str] = mapped_column(String(30), default="")
    reviewer: Mapped[str] = mapped_column(String(120), default="Local user")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class Activity(Base):
    __tablename__="activities"
    id: Mapped[int]=mapped_column(primary_key=True)
    project_id: Mapped[int]=mapped_column(ForeignKey("projects.id"))
    event: Mapped[str]=mapped_column(String(300))
    details: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now_utc)
class ScanCheck(Base):
    __tablename__="scan_checks"
    id: Mapped[int]=mapped_column(primary_key=True)
    project_id: Mapped[int]=mapped_column(ForeignKey("projects.id"))
    asset: Mapped[str]=mapped_column(String(2048))
    check_name: Mapped[str]=mapped_column(String(120))
    outcome: Mapped[str]=mapped_column(String(40))
    details: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now_utc)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    endpoint_type: Mapped[str] = mapped_column(
        String(80), default="Web page"
    )
    method: Mapped[str] = mapped_column(String(12), default="GET")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    category: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(250))
    target: Mapped[str] = mapped_column(String(2048), default="")
    status: Mapped[str] = mapped_column(String(40), default="Planned")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )




class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True, index=True
    )
    test_case_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_cases.id"), nullable=True, index=True
    )
    scan_check_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_checks.id"), nullable=True, index=True
    )
    original_name: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(2048))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(default=0)
    content_type: Mapped[str] = mapped_column(
        String(150), default="application/octet-stream"
    )
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class AssessmentJob(Base):
    __tablename__ = "assessment_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    job_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(40), default="queued")
    progress: Mapped[int] = mapped_column(default=0)
    checkpoint: Mapped[str] = mapped_column(Text, default="")
    input_json: Mapped[str] = mapped_column(Text, default="{}")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ProgramPolicy(Base):
    """Immutable-by-convention snapshot of an analyzed bounty policy."""
    __tablename__ = "program_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    version_number: Mapped[int] = mapped_column(default=1)
    provider_id: Mapped[str] = mapped_column(String(80), default="unknown")
    provider_name: Mapped[str] = mapped_column(String(160), default="")
    program_identifier: Mapped[str] = mapped_column(String(500), default="")
    source_url: Mapped[str] = mapped_column(String(2048), default="")
    source_type: Mapped[str] = mapped_column(String(80), default="")
    policy_text: Mapped[str] = mapped_column(Text, default="")
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    extraction_confidence: Mapped[str] = mapped_column(String(30), default="low")
    extraction_json: Mapped[str] = mapped_column(Text, default="{}")
    review_status: Mapped[str] = mapped_column(
        String(40), default="needs_review"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class ProgramAsset(Base):
    """An asset candidate extracted from a specific policy snapshot."""
    __tablename__ = "program_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("program_policies.id"), index=True
    )
    asset: Mapped[str] = mapped_column(String(2048))
    asset_type: Mapped[str] = mapped_column(String(80), default="hostname")
    disposition: Mapped[str] = mapped_column(String(40), default="ambiguous")
    confidence: Mapped[str] = mapped_column(String(30), default="low")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    source: Mapped[str] = mapped_column(String(80), default="")

    # Human review is independent of the extracted policy disposition.
    review_status: Mapped[str] = mapped_column(
        String(40), default="pending"
    )
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class TestCredentialProfile(Base):
    """Encrypted researcher-owned test-account credential, scoped to one host."""

    __tablename__ = "test_credential_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    host: Mapped[str] = mapped_column(String(253), index=True)
    name: Mapped[str] = mapped_column(String(120))
    role_label: Mapped[str] = mapped_column(String(80), default="test account")
    auth_type: Mapped[str] = mapped_column(String(20))
    encrypted_secret: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc
    )

class ResearcherOwnedResource(Base):
    """Encrypted mapping for a researcher-attested test resource."""

    __tablename__ = "researcher_owned_resources"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), index=True
    )
    host: Mapped[str] = mapped_column(String(253), index=True)
    endpoint_template: Mapped[str] = mapped_column(String(2048))
    owner_profile_id: Mapped[int] = mapped_column(
        ForeignKey("test_credential_profiles.id"), index=True
    )
    resource_fingerprint: Mapped[str] = mapped_column(
        String(64), index=True
    )
    encrypted_reference: Mapped[str] = mapped_column(Text)
    attestation_note: Mapped[str] = mapped_column(Text, default="")
    ownership_attested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )

