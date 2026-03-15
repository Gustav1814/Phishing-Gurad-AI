"""
PhishGuard AI — central config and paths.
Production: config in config/, model in models/, data in data/, DBs in instance/.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Project layout (production-ready)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.environ.get("PHISHGUARD_CONFIG_DIR", "").strip() or os.path.join(PROJECT_ROOT, "config")
MODELS_DIR = os.environ.get("PHISHGUARD_MODELS_DIR", "").strip() or os.path.join(PROJECT_ROOT, "models")
DATA_DIR = os.environ.get("PHISHGUARD_DATA_DIR", "").strip() or os.path.join(PROJECT_ROOT, "data")
INSTANCE_DIR = os.environ.get("PHISHGUARD_INSTANCE_DIR", "").strip() or os.path.join(PROJECT_ROOT, "instance")

# AI Provider: "local" (trained model, default) | "custom" (HTTP endpoint) | "rules" (rule-based only)
AI_PROVIDER = os.getenv("AI_PROVIDER", "local").lower()

# Local trained model (AI_PROVIDER=local); prefer models/, fallback to root for backward compat
_candidate = os.getenv("TRAINED_MODEL_PATH", "").strip()
if _candidate:
    TRAINED_MODEL_PATH = _candidate
else:
    _in_models = os.path.join(MODELS_DIR, "trained_scanner.joblib")
    _in_root = os.path.join(PROJECT_ROOT, "trained_scanner.joblib")
    TRAINED_MODEL_PATH = _in_models if os.path.isfile(_in_models) else _in_root

# Custom AI (AI_PROVIDER=custom)
CUSTOM_AI_URL = os.getenv("CUSTOM_AI_URL", "").strip()
CUSTOM_AI_API_KEY = os.getenv("CUSTOM_AI_API_KEY", "").strip()
try:
    CUSTOM_AI_TIMEOUT = max(5, min(120, int(os.getenv("CUSTOM_AI_TIMEOUT", "30"))))
except (TypeError, ValueError):
    CUSTOM_AI_TIMEOUT = 30

# Optional Postgres for adaptive learning
DATABASE_URL = (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "").strip()

# Database paths
IS_SERVERLESS = os.getenv("VERCEL", "") or os.getenv("AWS_LAMBDA_FUNCTION_NAME", "")
if IS_SERVERLESS:
    DATABASE_PATH = "/tmp/phishing_emails.db"
else:
    DATABASE_PATH = os.getenv("DATABASE_PATH", "").strip() or os.path.join(INSTANCE_DIR, "phishing_emails.db")

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "phishing-trainer-dev-key")
DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"

# Scanner verdict thresholds (0-100). Tune for precision vs recall.
SCANNER_THRESHOLD_PHISHING = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_PHISHING", "65"))))
SCANNER_THRESHOLD_SUSPICIOUS = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_SUSPICIOUS", "40"))))
SCANNER_THRESHOLD_SPAM = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_SPAM", "22"))))
# Analysis cache TTL in seconds; 0 = disabled
ANALYSIS_CACHE_TTL_SEC = max(0, int(os.getenv("ANALYSIS_CACHE_TTL_SEC", "0")))


def ensure_dirs():
    """Create instance, models, data dirs if missing (skip on serverless)."""
    if IS_SERVERLESS:
        return
    for d in (INSTANCE_DIR, MODELS_DIR, DATA_DIR):
        if d:
            os.makedirs(d, exist_ok=True)
