from pathlib import Path
import os
APP_NAME = "BugHunter AI"
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("BUGHUNTER_DATA_DIR", ROOT / "data")).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "bughunter.db"
DATABASE_URL = os.environ.get("BUGHUNTER_DATABASE_URL", f"sqlite:///{DB_PATH}")
REQUEST_TIMEOUT = 8.0
USER_AGENT = "BugHunterAI-PersonalResearch/0.1 (authorized-scope-only)"

# Central API connection settings.
# Keep localhost as the default until remote deployment is configured.
API_BASE_URL = os.environ.get(
    "BUGHUNTER_API_URL",
    "http://127.0.0.1:8765",
).rstrip("/")
API_TIMEOUT = float(os.environ.get("BUGHUNTER_API_TIMEOUT", "10"))
