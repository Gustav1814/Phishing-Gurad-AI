"""
adaptive_learning.py — Dynamic, self-supervised learning layer for the inbox scanner.

Learns from every scan without manual labels:
- Domain reputation: sender domains that often appear in threat vs safe emails get a
  reputation delta that nudges future scores.
- Similar-email prior: past emails from the same domain (and similar link set) contribute
  a prior threat score that is blended with the current model output.
- Optional online classifier: a small SGD classifier is updated (partial_fit) on each
  scan using the current verdict as the label; its prediction is blended into the final
  score so the system adapts to the distribution of emails you see.

User feedback (submit_feedback) overrides the stored verdict for reputation and
optionally retrains the classifier, improving over time with corrections.
"""

import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Optional: online classifier (sklearn); if missing, only domain + similar-prior are used
try:
    from sklearn.linear_model import SGDClassifier
    import joblib
    import numpy as np
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False
    np = None

# DB path: use /tmp on Vercel (read-only filesystem); else project dir
_IS_SERVERLESS = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
_ADAPTIVE_DB = "/tmp/adaptive_learning.db" if _IS_SERVERLESS else os.path.join(os.path.dirname(__file__), "adaptive_learning.db")
_MODEL_PATH = "/tmp/adaptive_model.joblib" if _IS_SERVERLESS else os.path.join(os.path.dirname(__file__), "adaptive_model.joblib")

# Verdicts considered "threat" for reputation and classifier label
THREAT_VERDICTS = frozenset({"PHISHING", "SPAM", "SCAM", "SUSPICIOUS"})

# Trusted domains (subset); used for feature "is_trusted_sender"
TRUSTED_DOMAINS = frozenset({
    "linkedin.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "openai.com", "netflix.com", "paypal.com", "stripe.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com", "slack.com",
    "zoom.us", "dropbox.com", "adobe.com", "salesforce.com", "notion.so",
})


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_ADAPTIVE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT NOT NULL,
                sender_domain TEXT NOT NULL,
                link_domains_json TEXT,
                verdict TEXT NOT NULL,
                threat_score REAL NOT NULL,
                user_verdict TEXT,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(sender_domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(email_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")


def _email_fingerprint(email_data: Dict[str, Any]) -> str:
    """Stable hash for dedup and similar lookup: sender_domain + normalized subject + sorted link domains."""
    domain = (email_data.get("sender_email") or "").split("@")[-1].lower()
    subject = (email_data.get("subject") or "").strip().lower()[:200]
    links = email_data.get("links") or []
    domains = sorted({urlparse(link).netloc or "" for link in links if link.startswith("http")})
    link_part = "|".join(domains[:20])  # cap for stability
    raw = f"{domain}\n{subject}\n{link_part}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _link_domains(email_data: Dict[str, Any]) -> List[str]:
    links = email_data.get("links") or []
    return sorted({urlparse(link).netloc or "" for link in links if link.startswith("http")})[:30]


def _sender_domain(email_data: Dict[str, Any]) -> str:
    return (email_data.get("sender_email") or "").split("@")[-1].lower()


def _effective_verdict(row: sqlite3.Row) -> str:
    return (row["user_verdict"] or row["verdict"] or "SAFE").strip().upper()


def get_domain_reputation(sender_domain: str) -> Tuple[float, int, int]:
    """
    Returns (delta, threat_count, safe_count).
    delta is in [-25, +25]: positive = domain has been seen more in threats, negative = more in safe.
    """
    _init_db()
    if not sender_domain:
        return 0.0, 0, 0
    with _get_conn() as conn:
        cur = conn.execute(
            "SELECT verdict, user_verdict FROM scans WHERE sender_domain = ?",
            (sender_domain,),
        )
        rows = cur.fetchall()
    threat_count = 0
    safe_count = 0
    for row in rows:
        v = _effective_verdict(row)
        if v in THREAT_VERDICTS:
            threat_count += 1
        else:
            safe_count += 1
    total = threat_count + safe_count
    if total == 0:
        return 0.0, 0, 0
    threat_ratio = threat_count / total
    # delta: threat_ratio 1 -> +25, 0 -> -25, 0.5 -> 0
    delta = (threat_ratio - 0.5) * 50.0
    delta = max(-25.0, min(25.0, delta))
    return delta, threat_count, safe_count


def get_similar_past(sender_domain: str, link_domains: List[str], limit: int = 50) -> Tuple[float, int]:
    """
    Average threat_score from past scans with the same sender_domain.
    Returns (avg_threat_score, count). If no history, returns (0.0, 0).
    """
    _init_db()
    if not sender_domain:
        return 0.0, 0
    with _get_conn() as conn:
        cur = conn.execute(
            "SELECT threat_score, user_verdict, verdict FROM scans WHERE sender_domain = ? ORDER BY created_at DESC LIMIT ?",
            (sender_domain, limit),
        )
        rows = cur.fetchall()
    if not rows:
        return 0.0, 0
    # Prefer user_verdict for weighting: if user said threat, use threat_score as-is; if safe, treat as 0
    scores = []
    for row in rows:
        v = _effective_verdict(row)
        sc = row["threat_score"]
        if v not in THREAT_VERDICTS:
            sc = min(sc, 15)  # cap safe emails so they don't pull average up
        scores.append(sc)
    return sum(scores) / len(scores), len(scores)


def get_adaptive_delta(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute score adjustment from learned signals (no current-scan data).
    Returns dict: domain_delta, similar_prior, similar_count, learned_score (if classifier),
    combined_delta, explanation.
    """
    domain = _sender_domain(email_data)
    link_doms = _link_domains(email_data)

    domain_delta, threat_count, safe_count = get_domain_reputation(domain)
    similar_avg, similar_count = get_similar_past(domain, link_doms)

    # similar_prior: blend past average into a delta. If past avg is 60 and current will be 30, we'd push up.
    # We don't have "current" here; we return similar_avg and similar_count so caller can blend.
    similar_prior_delta = 0.0
    if similar_count >= 2 and similar_avg >= 40:
        similar_prior_delta = min(15, (similar_avg - 50) * 0.3)  # push up if past was threatening
    elif similar_count >= 2 and similar_avg < 20:
        similar_prior_delta = max(-15, (similar_avg - 50) * 0.3)  # push down if past was safe

    learned_score: Optional[float] = None
    learned_delta = 0.0
    if _HAS_SKLEARN:
        try:
            features = _extract_features(email_data)
            model = _load_model()
            if model is not None and features is not None:
                X = np.array([features], dtype=np.float64)
                proba = model.predict_proba(X)[0]
                # proba[1] = P(threat)
                learned_score = float(proba[1] * 100.0)
                learned_delta = (learned_score - 50.0) * 0.4  # -20 to +20
                learned_delta = max(-20, min(20, learned_delta))
        except Exception:
            learned_score = None
            learned_delta = 0.0

    combined_delta = domain_delta + similar_prior_delta + learned_delta
    combined_delta = max(-40, min(40, combined_delta))

    explanation_parts = []
    if domain_delta != 0:
        explanation_parts.append(f"Domain reputation ({domain}): {threat_count} threat, {safe_count} safe → delta {domain_delta:+.0f}")
    if similar_count >= 2:
        explanation_parts.append(f"Similar past emails from this domain (n={similar_count}): avg score {similar_avg:.0f} → prior delta {similar_prior_delta:+.0f}")
    if learned_score is not None:
        explanation_parts.append(f"Online model prediction: {learned_score:.0f}/100 → delta {learned_delta:+.0f}")

    return {
        "email_hash": _email_fingerprint(email_data),
        "domain_delta": round(domain_delta, 1),
        "domain_threat_count": threat_count,
        "domain_safe_count": safe_count,
        "similar_prior": round(similar_avg, 1),
        "similar_count": similar_count,
        "learned_score": round(learned_score, 1) if learned_score is not None else None,
        "learned_delta": round(learned_delta, 1),
        "combined_delta": round(combined_delta, 1),
        "explanation": " | ".join(explanation_parts) if explanation_parts else "No prior data yet",
    }


def _extract_features(email_data: Dict[str, Any]) -> Optional[List[float]]:
    """Feature vector for the online classifier. Same order every time."""
    domain = _sender_domain(email_data)
    links = email_data.get("links") or []
    subject = (email_data.get("subject") or "")[:500]
    body = (email_data.get("body_text") or "")[:3000]
    if not body and email_data.get("body_html"):
        import re
        body = re.sub("<[^>]+>", "", (email_data.get("body_html") or ""))[:3000]
    attachments = email_data.get("attachments") or []

    # Numeric features (fixed size)
    domain_hash = (hash(domain) % 1000) / 1000.0
    n_links = min(len(links), 20) / 20.0
    has_shortener = 1.0 if any(s in " ".join(links).lower() for s in ("bit.ly", "tinyurl", "goo.gl", "t.co")) else 0.0
    subject_len = min(len(subject), 500) / 500.0
    body_len = min(len(body), 5000) / 5000.0
    n_attachments = min(len(attachments), 10) / 10.0
    is_trusted = 1.0 if any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS) else 0.0
    return [domain_hash, n_links, has_shortener, subject_len, body_len, n_attachments, is_trusted]


def _load_model() -> Optional[Any]:
    """Load SGDClassifier from disk. Features are already in [0,1], no scaler needed."""
    if not _HAS_SKLEARN:
        return None
    try:
        if os.path.isfile(_MODEL_PATH):
            obj = joblib.load(_MODEL_PATH)
            return obj.get("model")
    except Exception:
        pass
    return None


def _save_model(model: Any) -> None:
    if not _HAS_SKLEARN:
        return
    try:
        joblib.dump({"model": model}, _MODEL_PATH)
    except Exception:
        pass


def record_scan(email_data: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    """
    Persist this scan for future learning. If sklearn is available, also update the
    online classifier with (features from email_data, label from analysis verdict).
    """
    _init_db()
    email_hash = _email_fingerprint(email_data)
    sender_domain = _sender_domain(email_data)
    link_domains = _link_domains(email_data)
    verdict = (analysis.get("verdict") or "SAFE").strip().upper()
    threat_score = float(analysis.get("threat_score", 0))

    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO scans (email_hash, sender_domain, link_domains_json, verdict, threat_score, user_verdict, created_at)
               VALUES (?, ?, ?, ?, ?, NULL, ?)""",
            (email_hash, sender_domain, json.dumps(link_domains), verdict, threat_score, time.time()),
        )

    # Online classifier: partial_fit with this sample (self-supervised: label = current verdict)
    if _HAS_SKLEARN and np is not None:
        try:
            features = _extract_features(email_data)
            if features is None:
                return
            label = 1 if verdict in THREAT_VERDICTS else 0
            model = _load_model()
            X = np.array([features], dtype=np.float64)
            y = np.array([label])
            if model is None:
                model = SGDClassifier(loss="log_loss", random_state=42, max_iter=1, warm_start=True)
            model.partial_fit(X, y, classes=[0, 1])
            _save_model(model)
        except Exception:
            pass


def submit_feedback(email_hash: str, correct_verdict: str) -> bool:
    """
    Record user correction for a past scan. Updates the most recent scan with this
    email_hash (or any scan with matching hash). Use the same hash as in analysis
    (we expose it in the analysis object).
    correct_verdict: e.g. "SAFE", "PHISHING", "SPAM"
    """
    _init_db()
    v = correct_verdict.strip().upper()
    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE scans SET user_verdict = ? WHERE email_hash = ?",
            (v, email_hash),
        )
        return cur.rowcount > 0


def get_adaptive_info(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns the email fingerprint (hash) for use in feedback, plus current
    domain reputation. Useful for UI to show "learned" state and to call
    submit_feedback with the same hash.
    """
    domain = _sender_domain(email_data)
    delta, threat_count, safe_count = get_domain_reputation(domain)
    return {
        "email_hash": _email_fingerprint(email_data),
        "sender_domain": domain,
        "domain_reputation": {"threat_count": threat_count, "safe_count": safe_count, "delta": round(delta, 1)},
    }
