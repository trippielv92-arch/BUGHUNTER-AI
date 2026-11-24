import tomllib
from pathlib import Path


def test_project_metadata_uses_release_candidate_version():
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    assert metadata["project"]["version"] == "0.4.0rc1"
