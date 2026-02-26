#!/usr/bin/env python3
"""Print where the trained scanner model is and whether it exists. Run from project root."""
import os
import sys

# Load config from project
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

path = getattr(config, "TRAINED_MODEL_PATH", "")
if not path:
    path = os.path.join(os.path.dirname(__file__), "trained_scanner.joblib")
path = os.path.normpath(os.path.abspath(path))
exists = os.path.isfile(path)
provider = getattr(config, "AI_PROVIDER", "fallback")

print("Trained scanner model")
print("  Path:   ", path)
print("  Exists: ", "Yes" if exists else "No (run train_scanner_model.py first)")
print("  AI_PROVIDER: ", provider)
if provider == "local" and not exists:
    print("  → Set AI_PROVIDER=local only after training. For now use AI_PROVIDER=fallback or train first.")
