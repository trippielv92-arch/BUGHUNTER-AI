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

# The supported desktop experience is cloud-first. Local SQLite mode is
# intentionally hidden unless a developer explicitly opts in.
API_BASE_URL = os.environ.get(
    "BUGHUNTER_API_URL",
    "https://bughunter-ai-ebon.vercel.app",
).rstrip("/")
API_TIMEOUT = float(os.environ.get("BUGHUNTER_API_TIMEOUT", "20"))
ENABLE_LOCAL_MODE = os.environ.get(
    "BUGHUNTER_ENABLE_LOCAL_MODE", ""
).strip().lower() in {"1", "true", "yes"}
