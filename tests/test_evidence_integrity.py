from pathlib import Path

from app.services import evidence
from app.services.projects import create_project


def test_evidence_digest_detects_tampering_without_mutating_record(
    db, tmp_path, monkeypatch
):
    project = create_project(db, "Evidence integrity project")
    vault = tmp_path / "persistent-evidence"
    monkeypatch.setattr(evidence, "DATA_DIR", vault)

    source = tmp_path / "response-capture.txt"
    source.write_bytes(b"HTTP/1.1 200 OK\\nContent-Type: text/plain\\n\\nsynthetic evidence")

    record = evidence.add_evidence(
        db,
        project.id,
        source,
        notes="Synthetic test evidence",
    )

    original_digest = record.sha256
    stored_path = Path(record.stored_path)

    assert evidence.verify_evidence(record) is True
    stored_path.write_bytes(b"modified evidence")
    assert evidence.verify_evidence(record) is False
    assert record.sha256 == original_digest
    assert record.size_bytes != stored_path.stat().st_size
