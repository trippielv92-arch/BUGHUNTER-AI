import hashlib
import mimetypes
from pathlib import Path
import json
import uuid

from sqlalchemy import select
from app.models.entities import Evidence, Finding, TestCase, ScanCheck, Activity
from app.services.projects import require_active_project
from app.core.config import DATA_DIR

MAX_EVIDENCE_SIZE = 25 * 1024 * 1024


def _evidence_directory_path(project_id):
    return DATA_DIR / "evidence" / str(project_id)


def _evidence_directory_candidates(project_id):
    configured = _evidence_directory_path(project_id)
    legacy = (
        Path(__file__).resolve().parents[2]
        / "data" / "evidence" / str(project_id)
    )

    candidates = []
    seen = set()
    for directory in (configured, legacy):
        key = str(directory.resolve(strict=False))
        if key not in seen:
            seen.add(key)
            candidates.append(directory)

    return candidates


def _validated_evidence_path(stored_path, project_id):
    stored = Path(stored_path)
    if not stored.is_absolute():
        raise ValueError("Evidence path is not absolute.")

    cursor = stored
    while True:
        if cursor.is_symlink():
            raise ValueError("Evidence path contains a symbolic link.")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent

    resolved = stored.resolve(strict=True)

    for vault in _evidence_directory_candidates(project_id):
        if vault.is_symlink():
            continue
        try:
            resolved.relative_to(vault.resolve(strict=False))
            return resolved, vault
        except ValueError:
            continue

    raise ValueError("Evidence path is outside the approved project vaults.")


def evidence_directory(project_id):
    directory = _evidence_directory_path(project_id)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def add_evidence(
    db, project_id, source_path, notes="",
    finding_id=None, test_case_id=None, scan_check_id=None
):
    project = require_active_project(db, project_id)

    source = Path(source_path).expanduser().resolve()
    if not source.is_file():
        raise ValueError("Evidence source must be an existing file.")

    size = source.stat().st_size
    if size <= 0:
        raise ValueError("Empty evidence files are not accepted.")
    if size > MAX_EVIDENCE_SIZE:
        raise ValueError("Evidence file exceeds the 25 MB limit.")

    if finding_id is not None:
        finding = db.get(Finding, finding_id)
        if not finding or finding.project_id != project_id:
            raise ValueError("Finding does not belong to this project.")

    if test_case_id is not None:
        test_case = db.get(TestCase, test_case_id)
        if not test_case or test_case.project_id != project_id:
            raise ValueError("Assessment test does not belong to this project.")

    if scan_check_id is not None:
        scan_check = db.get(ScanCheck, scan_check_id)
        if not scan_check or scan_check.project_id != project_id:
            raise ValueError("Assessment observation does not belong to this project.")

        if test_case_id is not None:
            try:
                observation = json.loads(scan_check.details or "{}")
            except (TypeError, ValueError):
                observation = {}

            if observation.get("test_case_id") != test_case_id:
                raise ValueError(
                    "The selected observation does not belong to this assessment test."
                )

    # If a test is selected, automatically link its latest recorded observation.
    if test_case_id is not None and scan_check_id is None:
        checks = db.scalars(
            select(ScanCheck)
            .where(ScanCheck.project_id == project_id)
            .order_by(ScanCheck.created_at.desc())
        ).all()

        for check in checks:
            try:
                observation = json.loads(check.details or "{}")
            except (TypeError, ValueError):
                continue

            if observation.get("test_case_id") == test_case_id:
                scan_check_id = check.id
                break

    directory = evidence_directory(project_id)
    safe_suffix = source.suffix[:20]
    destination = directory / f"{uuid.uuid4().hex}{safe_suffix}"
    temporary = destination.with_name(destination.name + ".part")
    digest = hashlib.sha256()
    copied_size = 0

    try:
        with source.open("rb") as original, temporary.open("xb") as output:
            while True:
                chunk = original.read(1024 * 1024)
                if not chunk:
                    break

                copied_size += len(chunk)
                if copied_size > MAX_EVIDENCE_SIZE:
                    raise ValueError("Evidence file exceeds the 25 MB limit.")

                digest.update(chunk)
                output.write(chunk)

        if copied_size <= 0:
            raise ValueError("Empty evidence files are not accepted.")

        temporary.replace(destination)

        record = Evidence(
            project_id=project_id,
            finding_id=finding_id,
            test_case_id=test_case_id,
            scan_check_id=scan_check_id,
            original_name=source.name[:255],
            stored_path=str(destination),
            sha256=digest.hexdigest(),
            size_bytes=copied_size,
            content_type=(
                mimetypes.guess_type(source.name)[0]
                or "application/octet-stream"
            ),
            notes=notes[:10000],
        )

        db.add(record)
        db.add(Activity(
            project_id=project_id,
            event="Evidence added",
            details=f"Evidence upload: {source.name}",
        ))

        # Evidence metadata and its audit event commit together.
        commit_attempted = True
        db.commit()
        db.refresh(record)
        return record

    except Exception:
        db.rollback()
        temporary.unlink(missing_ok=True)

        # If commit was attempted, its outcome may be uncertain
        # (for example, a lost database connection). Preserve the file
        # rather than risk deleting a file whose row was committed.
        if not locals().get("commit_attempted", False):
            destination.unlink(missing_ok=True)
        raise


def list_evidence(db, project_id):
    from sqlalchemy import select

    return db.scalars(
        select(Evidence)
        .where(Evidence.project_id == project_id)
        .order_by(Evidence.created_at.desc())
    ).all()


def verify_evidence(record):
    try:
        path, _vault = _validated_evidence_path(
            record.stored_path, record.project_id
        )

        if not path.is_file():
            return False

        digest = hashlib.sha256()
        actual_size = 0

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                actual_size += len(chunk)
                if actual_size > MAX_EVIDENCE_SIZE:
                    return False
                digest.update(chunk)

        return (
            actual_size == record.size_bytes
            and digest.hexdigest() == record.sha256
        )

    except (OSError, ValueError, TypeError, RuntimeError):
        return False



def audit_project_evidence(db, project_id):
    """
    Read-only integrity and reference audit for one project's evidence vault.
    Never repairs, rewrites, deletes, or changes evidence records.
    """
    from app.models.entities import Project

    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found.")

    records = db.scalars(
        select(Evidence)
        .where(Evidence.project_id == project_id)
        .order_by(Evidence.created_at.desc())
    ).all()

    finding_ids = set(db.scalars(
        select(Finding.id).where(Finding.project_id == project_id)
    ).all())
    test_case_ids = set(db.scalars(
        select(TestCase.id).where(TestCase.project_id == project_id)
    ).all())
    scan_check_ids = set(db.scalars(
        select(ScanCheck.id).where(ScanCheck.project_id == project_id)
    ).all())

    expected_directory = _evidence_directory_path(project_id)

    summary = {
        "total": len(records),
        "verified": 0,
        "missing": 0,
        "invalid_path": 0,
        "size_mismatch": 0,
        "hash_mismatch": 0,
        "oversized": 0,
        "invalid_metadata": 0,
        "unreadable": 0,
        "broken_reference": 0,
        "unlinked": 0,
        "valid_references": 0,
    }
    audited = []

    for record in records:
        file_status = "unreadable"
        file_reason = "File could not be inspected."
        actual_size = None

        try:
            if (
                record.size_bytes is None
                or record.size_bytes <= 0
                or record.size_bytes > MAX_EVIDENCE_SIZE
                or not isinstance(record.sha256, str)
                or len(record.sha256) != 64
            ):
                file_status = "invalid_metadata"
                file_reason = "Stored size or SHA-256 metadata is invalid."
            else:
                stored = Path(record.stored_path)
                resolved, vault = _validated_evidence_path(
                    stored, project_id
                )

                if not resolved.is_file():
                    file_status = "invalid_path"
                    file_reason = "Stored evidence path is not a regular file."
                else:
                    actual_size = resolved.stat().st_size

                    if actual_size > MAX_EVIDENCE_SIZE:
                        file_status = "oversized"
                        file_reason = "Stored file exceeds the 25 MB evidence limit."
                    elif actual_size != record.size_bytes:
                        file_status = "size_mismatch"
                        file_reason = (
                            f"Stored size is {record.size_bytes} bytes; "
                            f"actual size is {actual_size} bytes."
                        )
                    else:
                        digest = hashlib.sha256()
                        with resolved.open("rb") as stream:
                            for chunk in iter(
                                lambda: stream.read(1024 * 1024), b""
                            ):
                                digest.update(chunk)

                        if digest.hexdigest().lower() != record.sha256.lower():
                            file_status = "hash_mismatch"
                            file_reason = (
                                "File SHA-256 differs from the stored digest."
                            )
                        else:
                            file_status = "verified"
                            file_reason = "File size and SHA-256 match."


        except FileNotFoundError:
            file_status = "missing"
            file_reason = "Evidence file or its directory is missing."
        except (OSError, ValueError, TypeError, RuntimeError):
            file_status = "invalid_path"
            file_reason = (
                "Path is invalid, outside the project vault, or cannot be accessed."
            )

        reference_problems = []
        if record.finding_id is not None and record.finding_id not in finding_ids:
            reference_problems.append(
                f"Finding #{record.finding_id} is missing or belongs to another project."
            )
        if record.test_case_id is not None and record.test_case_id not in test_case_ids:
            reference_problems.append(
                f"Test case #{record.test_case_id} is missing or belongs to another project."
            )
        if record.scan_check_id is not None and record.scan_check_id not in scan_check_ids:
            reference_problems.append(
                f"Scan observation #{record.scan_check_id} is missing or belongs to another project."
            )

        if reference_problems:
            reference_status = "broken_reference"
            reference_reason = " ".join(reference_problems)
        elif (
            record.finding_id is None
            and record.test_case_id is None
            and record.scan_check_id is None
        ):
            reference_status = "unlinked"
            reference_reason = "No finding, test case, or scan observation is linked."
        else:
            reference_status = "valid"
            reference_reason = "All linked records belong to this project."

        summary[file_status] = summary.get(file_status, 0) + 1
        if reference_status == "broken_reference":
            summary["broken_reference"] += 1
        elif reference_status == "unlinked":
            summary["unlinked"] += 1
        else:
            summary["valid_references"] += 1

        audited.append({
            "id": record.id,
            "name": record.original_name,
            "file_integrity": file_status,
            "file_reason": file_reason,
            "reference_integrity": reference_status,
            "reference_reason": reference_reason,
            "actual_size_bytes": actual_size,
        })

    return {"summary": summary, "records": audited}
