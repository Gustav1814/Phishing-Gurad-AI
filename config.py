import os
from dotenv import load_dotenv

load_dotenv()

# AI Provider: "gemini" (free) or "fallback" (no API key needed)
AI_PROVIDER = os.getenv("AI_PROVIDER", "fallback").lower()

# Google Gemini API Key (free tier at https://aistudio.google.com/apikey)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Gemini model
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Database — use /tmp on serverless (Vercel/Lambda) since project dir is read-only
IS_SERVERLESS = os.getenv("VERCEL", "") or os.getenv("AWS_LAMBDA_FUNCTION_NAME", "")
if IS_SERVERLESS:
    DATABASE_PATH = "/tmp/phishing_emails.db"
else:
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "phishing_emails.db")

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "phishing-trainer-dev-key")
DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
