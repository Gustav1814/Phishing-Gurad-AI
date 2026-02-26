import os
from dotenv import load_dotenv

load_dotenv()

# AI Provider: "gemini" | "fallback" | "custom" | "local" (your trained model, no API)
AI_PROVIDER = os.getenv("AI_PROVIDER", "fallback").lower()

# Local trained model (when AI_PROVIDER=local) — no API key, no quota
TRAINED_MODEL_PATH = os.getenv("TRAINED_MODEL_PATH", "").strip() or os.path.join(
    os.path.dirname(__file__), "trained_scanner.joblib"
)

# Google Gemini API Key (free tier at https://aistudio.google.com/apikey)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Gemini model
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Custom AI (your own model) — runs dynamically per email
CUSTOM_AI_URL = os.getenv("CUSTOM_AI_URL", "").strip()  # e.g. http://localhost:8000/analyze
CUSTOM_AI_API_KEY = os.getenv("CUSTOM_AI_API_KEY", "").strip()  # optional Bearer token
CUSTOM_AI_TIMEOUT = max(5, min(120, int(os.getenv("CUSTOM_AI_TIMEOUT", "30"))))

# Optional Postgres for adaptive learning (persistent on Vercel). If set, scans/feedback persist across requests.
DATABASE_URL = (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "").strip()

# Database — use /tmp on serverless (Vercel/Lambda) since project dir is read-only
IS_SERVERLESS = os.getenv("VERCEL", "") or os.getenv("AWS_LAMBDA_FUNCTION_NAME", "")
if IS_SERVERLESS:
    DATABASE_PATH = "/tmp/phishing_emails.db"
else:
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "phishing_emails.db")

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "phishing-trainer-dev-key")
DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"

# Scanner verdict thresholds (0-100). Tune for precision vs recall.
SCANNER_THRESHOLD_PHISHING = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_PHISHING", "65"))))
SCANNER_THRESHOLD_SUSPICIOUS = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_SUSPICIOUS", "40"))))
SCANNER_THRESHOLD_SPAM = max(1, min(99, int(os.getenv("SCANNER_THRESHOLD_SPAM", "22"))))
# Analysis cache TTL in seconds; 0 = disabled. Reduces re-analysis of same email in batch/session.
ANALYSIS_CACHE_TTL_SEC = max(0, int(os.getenv("ANALYSIS_CACHE_TTL_SEC", "0")))
