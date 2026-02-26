"""
scanner_config_loader.py — Dynamic scanner config (thresholds, no restart).
Loads from scanner_config.json; falls back to env/config. API can update and persist.
"""

import json
import os
from typing import Any, Dict, Tuple

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_PROJECT_DIR, "scanner_config.json")
_RULES_PATH = os.path.join(_PROJECT_DIR, "scanner_rules.json")

# In-memory cache; cleared when file is updated via API
_cached_config: Dict[str, Any] = {}
_cached_rules: Dict[str, list] = {}
_config_mtime: float = 0
_rules_mtime: float = 0


def _load_config() -> Dict[str, Any]:
    global _cached_config, _config_mtime
    try:
        mtime = os.path.getmtime(_CONFIG_PATH) if os.path.isfile(_CONFIG_PATH) else 0
        if mtime != _config_mtime or not _cached_config:
            _config_mtime = mtime
            if os.path.isfile(_CONFIG_PATH):
                with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                    _cached_config = json.load(f)
            else:
                _cached_config = {}
    except Exception:
        _cached_config = {}
    return _cached_config


def get_thresholds(config_fallback: Any = None) -> Tuple[int, int, int]:
    """Return (phishing_min, suspicious_min, spam_min). Dynamic: reads from scanner_config.json then env."""
    cfg = _load_config()
    if config_fallback is None:
        try:
            import config as _config
            config_fallback = _config
        except ImportError:
            config_fallback = None
    def clamp(v: int) -> int:
        return max(1, min(99, int(v)))
    thr_p = cfg.get("threshold_phishing")
    thr_s = cfg.get("threshold_suspicious")
    thr_sp = cfg.get("threshold_spam")
    if thr_p is None and config_fallback:
        thr_p = getattr(config_fallback, "SCANNER_THRESHOLD_PHISHING", 65)
    if thr_s is None and config_fallback:
        thr_s = getattr(config_fallback, "SCANNER_THRESHOLD_SUSPICIOUS", 40)
    if thr_sp is None and config_fallback:
        thr_sp = getattr(config_fallback, "SCANNER_THRESHOLD_SPAM", 22)
    return (
        clamp(thr_p if thr_p is not None else 65),
        clamp(thr_s if thr_s is not None else 40),
        clamp(thr_sp if thr_sp is not None else 22),
    )


def set_thresholds(phishing: int, suspicious: int, spam: int) -> bool:
    """Persist thresholds to scanner_config.json. Returns True on success."""
    global _cached_config, _config_mtime
    try:
        cfg = _load_config().copy()
        cfg["threshold_phishing"] = max(1, min(99, int(phishing)))
        cfg["threshold_suspicious"] = max(1, min(99, int(suspicious)))
        cfg["threshold_spam"] = max(1, min(99, int(spam)))
        with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        _cached_config = cfg
        _config_mtime = os.path.getmtime(_CONFIG_PATH)
        return True
    except Exception:
        return False


# Built-in rule lists (used when scanner_rules.json is empty or missing)
_BUILTIN_CRED = ["verify your account", "confirm your identity", "update your password", "enter your credentials", "click here to verify", "validate your login", "sign in to confirm", "re-enter your password", "account verification required"]
_BUILTIN_URGENCY = ["act now", "suspended", "unauthorized", "terminated", "within 24 hours", "within 2 hours", "failure to comply", "last warning", "final notice", "immediately", "urgent action required"]
_BUILTIN_BEC = ["wire transfer", "new bank account", "change of payment details", "urgent wire", "ceo request", "executive request", "vendor payment", "update our records", "send payment to", "as per our ceo", "confidential request"]
_BUILTIN_SCAM = ["million dollars", "inheritance", "unclaimed funds", "lottery winner", "congratulations you have won", "western union", "bitcoin opportunity", "crypto investment", "double your money", "guaranteed return", "beneficiary", "next of kin", "prince", "nigerian", "offshore account"]
_BUILTIN_TECH = ["your device is infected", "call this number", "microsoft support", "apple support", "virus detected", "remote access", "tech support callback", "your computer has been compromised"]
_BUILTIN_SPAM = ["weight loss", "enlargement", "limited time offer", "buy now", "discount code", "no obligation", "act now and save", "you have been selected", "click below to claim", "100% free", "earn money fast", "work from home opportunity"]


def _load_rules() -> Dict[str, list]:
    global _cached_rules, _rules_mtime
    try:
        mtime = os.path.getmtime(_RULES_PATH) if os.path.isfile(_RULES_PATH) else 0
        if mtime != _rules_mtime or not _cached_rules:
            _rules_mtime = mtime
            if os.path.isfile(_RULES_PATH):
                with open(_RULES_PATH, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                # Merge with builtin: custom list extends builtin
                _cached_rules = {
                    "cred_patterns": _BUILTIN_CRED + [x for x in (raw.get("cred_patterns") or []) if x and isinstance(x, str)],
                    "urgency": _BUILTIN_URGENCY + [x for x in (raw.get("urgency") or []) if x and isinstance(x, str)],
                    "bec_patterns": _BUILTIN_BEC + [x for x in (raw.get("bec_patterns") or []) if x and isinstance(x, str)],
                    "scam_patterns": _BUILTIN_SCAM + [x for x in (raw.get("scam_patterns") or []) if x and isinstance(x, str)],
                    "tech_support": _BUILTIN_TECH + [x for x in (raw.get("tech_support") or []) if x and isinstance(x, str)],
                    "spam_patterns": _BUILTIN_SPAM + [x for x in (raw.get("spam_patterns") or []) if x and isinstance(x, str)],
                }
            else:
                _cached_rules = {
                    "cred_patterns": _BUILTIN_CRED,
                    "urgency": _BUILTIN_URGENCY,
                    "bec_patterns": _BUILTIN_BEC,
                    "scam_patterns": _BUILTIN_SCAM,
                    "tech_support": _BUILTIN_TECH,
                    "spam_patterns": _BUILTIN_SPAM,
                }
    except Exception:
        _cached_rules = {
            "cred_patterns": _BUILTIN_CRED,
            "urgency": _BUILTIN_URGENCY,
            "bec_patterns": _BUILTIN_BEC,
            "scam_patterns": _BUILTIN_SCAM,
            "tech_support": _BUILTIN_TECH,
            "spam_patterns": _BUILTIN_SPAM,
        }
    return _cached_rules


def get_dynamic_rules() -> Dict[str, list]:
    """Return merged rule lists (builtin + scanner_rules.json). Dynamic: file reload on change."""
    return _load_rules().copy()


def update_rules(updates: Dict[str, list]) -> bool:
    """Persist extra rules to scanner_rules.json. Keys: cred_patterns, urgency, bec_patterns, scam_patterns, tech_support, spam_patterns. Values extend builtin."""
    global _cached_rules, _rules_mtime
    try:
        path = _RULES_PATH
        existing = {}
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        for k, v in (updates or {}).items():
            if k in ("cred_patterns", "urgency", "bec_patterns", "scam_patterns", "tech_support", "spam_patterns") and isinstance(v, list):
                existing[k] = [str(x).strip().lower() for x in v if x]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        _rules_mtime = 0
        _cached_rules = {}
        _load_rules()
        return True
    except Exception:
        return False


def reload_config() -> None:
    """Force reload of config and rules from disk."""
    global _cached_config, _cached_rules, _config_mtime, _rules_mtime
    _cached_config = {}
    _cached_rules = {}
    _config_mtime = 0
    _rules_mtime = 0
