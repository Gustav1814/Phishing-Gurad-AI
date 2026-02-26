"""
inbox_scanner.py — Full-Spectrum Adaptive AI Email Threat Analyzer
Connects to IMAP and uses Google Gemini AI for real-time classification of
phishing, scams, spam, BEC, malware delivery, impersonation, and social engineering.
"""

import imaplib
import email
import hashlib
import os
import time
import urllib.request
import urllib.error
from email.header import decode_header
from email.utils import parseaddr
from urllib.parse import urlparse
import html
import re
import json
import traceback
from typing import Dict, List, Optional, Tuple

import google.generativeai as genai
import config

# Optional in-memory analysis cache (keyed by email fingerprint, TTL from config)
_analysis_cache: Dict[str, Tuple[Dict, float]] = {}

# Cached trained model (loaded once when AI_PROVIDER=local)
_trained_model_obj: Optional[Any] = None

try:
    from adaptive_learning import get_adaptive_delta, record_scan, submit_feedback, get_adaptive_info
    _ADAPTIVE_AVAILABLE = True
except ImportError:
    _ADAPTIVE_AVAILABLE = False

try:
    from threat_intel import check_sender_domain as threat_intel_check_domain
except ImportError:
    threat_intel_check_domain = None


# ─── Helper Functions ───────────────────────────────────────────────────────────

def decode_mime_header(header_val):
    """Decode MIME-encoded email header to str."""
    if not header_val:
        return ""
    decoded_parts = decode_header(header_val)
    header_str = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            try:
                header_str += part.decode(encoding or "utf-8", errors="ignore")
            except LookupError:
                header_str += part.decode("utf-8", errors="ignore")
        else:
            header_str += str(part)
    return header_str


def extract_text_from_part(part):
    """Extract text content from an email part."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="ignore")
    except LookupError:
        return payload.decode("utf-8", errors="ignore")


def _parse_authentication_results(msg) -> Dict[str, str]:
    """
    Parse Authentication-Results (and common variants) for SPF/DKIM/DMARC.
    Returns {"spf": "pass"|"fail"|"none", "dkim": "...", "dmarc": "..."}.
    Industry standard: fail/none on a brand-claiming sender = strong spoof signal.
    """
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    raw = msg.get("Authentication-Results") or msg.get("X-Microsoft-Antispam") or ""
    if not raw:
        # Some providers use X-*-Auth headers
        for key in list(msg.keys()):
            if key and "auth" in key.lower() and "result" in key.lower():
                raw = raw + " " + (msg.get(key) or "")
    raw = raw.lower()
    for method in ("spf", "dkim", "dmarc"):
        # Match: spf=pass, dkim=fail (reason), dmarc=none
        m = re.search(rf"\b{method}\s*=\s*(pass|fail|none|neutral|softpass|temperror|permerror)", raw)
        if m:
            val = m.group(1)
            if val in ("pass", "softpass"):
                result[method] = "pass"
            elif val in ("fail", "permerror"):
                result[method] = "fail"
            else:
                result[method] = "none"
    return result


def extract_email_content(msg):
    """Extract subject, sender, date, body, headers, auth, and link analysis from an email.Message object."""
    subject = decode_mime_header(msg.get("Subject", "No Subject"))
    sender = decode_mime_header(msg.get("From", "Unknown Sender"))
    date = decode_mime_header(msg.get("Date", "Unknown Date"))
    reply_to = decode_mime_header(msg.get("Reply-To", ""))
    return_path = decode_mime_header(msg.get("Return-Path", ""))
    list_unsubscribe = decode_mime_header(msg.get("List-Unsubscribe", "") or msg.get("List-Unsubscribe-Post", ""))

    sender_name, sender_email = parseaddr(sender)
    reply_to_name, reply_to_email = parseaddr(reply_to) if reply_to else ("", "")

    body_text = ""
    body_html = ""
    attachments = []  # legacy: list of filenames
    attachment_details = []  # list of {"filename", "content_type"} for industry checks
    links = []
    link_display_pairs = []  # (display_text, href) for mismatch detection

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = decode_mime_header(part.get_filename())
                if filename:
                    attachments.append(filename)
                    attachment_details.append({"filename": filename, "content_type": content_type})
                continue

            if content_type == "text/plain" and "attachment" not in content_disposition:
                body_text += extract_text_from_part(part)
            elif content_type == "text/html" and "attachment" not in content_disposition:
                body_html += extract_text_from_part(part)
    else:
        content_type = msg.get_content_type()
        payload = extract_text_from_part(msg)
        if content_type == "text/html":
            body_html = payload
        else:
            body_text = payload

    # Extract links and optional display text from HTML
    if body_html:
        # href with possible display text: <a href="url">text</a>
        for m in re.finditer(r'<a\s[^>]*href=[\'"]?([^\'" >]+)[\'"]?[^>]*>([^<]*)</a>', body_html, re.I | re.S):
            href, display = m.group(1).strip(), _strip_html(m.group(2)).strip()
            links.append(href)
            if display and href:
                link_display_pairs.append((display[:200], href))
        # Fallback: any href without capture
        for href in re.findall(r'href=[\'"]?([^\'" >]+)', body_html):
            if href not in links:
                links.append(href)

    if body_text:
        text_links = re.findall(r'(https?://[^\s\)\]\"\']+)', body_text)
        links.extend(text_links)

    auth = _parse_authentication_results(msg)

    return {
        "subject": subject,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "reply_to_email": reply_to_email or "",
        "return_path": return_path,
        "date": date,
        "body_text": body_text[:5000],
        "body_html": body_html[:5000],
        "attachments": attachments,
        "attachment_details": attachment_details,
        "links": list(set(links)),
        "link_display_pairs": link_display_pairs,
        "auth_results": auth,
        "list_unsubscribe": list_unsubscribe[:500] if list_unsubscribe else "",
    }


# ─── Detection Helpers (scoring & analysis) ────────────────────────────────────

# Severity weights for consistent scoring (max contribution per category capped in fallback)
SEVERITY_WEIGHTS = {"critical": 40, "high": 22, "medium": 12, "low": 5}

# Known brand domains for lookalike detection (subset; fallback has full trusted list)
BRAND_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "facebook.com", "linkedin.com", "twitter.com", "x.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "irs.gov", "amazon.co.uk",
]


def _domain_similarity(domain: str, brand: str) -> float:
    """Return similarity 0–1; 1 = exact match. Catches typosquatting (e.g. gmail.co, paypa1.com)."""
    if not domain or not brand:
        return 0.0
    domain, brand = domain.lower().strip(), brand.lower().strip()
    if domain == brand or domain.endswith("." + brand):
        return 1.0
    # Length difference penalty
    if abs(len(domain) - len(brand)) > 3:
        return 0.0
    # Simple char-level similarity: same length or off-by-one
    if len(domain) == len(brand):
        diffs = sum(1 for a, b in zip(domain, brand) if a != b)
        if diffs <= 1:
            return 1.0 - (diffs * 0.4)  # 1 char diff = 0.6
    # Substring / extra char (e.g. gmail.com.co)
    if brand in domain and len(domain) <= len(brand) + 4:
        return 0.7
    return 0.0


def is_lookalike_domain(sender_domain: str) -> Tuple[bool, str]:
    """
    Returns (is_lookalike, matched_brand).
    If sender mimics a known brand but isn't the real domain, return True and the brand name.
    """
    if not sender_domain:
        return False, ""
    sender_domain = sender_domain.lower().strip()
    for brand in BRAND_DOMAINS:
        sim = _domain_similarity(sender_domain, brand)
        if 0.4 <= sim < 1.0:  # Similar but not exact
            return True, brand
    return False, ""


def analyze_link_display_mismatch(link_display_pairs: list) -> List[Dict]:
    """
    Detect when display text looks like a safe URL but href points elsewhere (e.g. phishing).
    Returns list of red-flag dicts.
    """
    safe_domains = ["linkedin.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
                    "paypal.com", "github.com", "openai.com", "facebook.com", "netflix.com"]
    mismatches = []
    for display, href in link_display_pairs:
        if not href.startswith("http"):
            continue
        display_lower = display.lower()[:100]
        href_lower = href.lower()
        # Extract domain from href (simple)
        try:
            href_domain = urlparse(href).netloc or ""
        except Exception:
            href_domain = ""
        # Display suggests a safe brand but href is different
        for safe in safe_domains:
            if safe in display_lower and safe not in href_domain:
                mismatches.append({
                    "flag": "Link display mismatch",
                    "severity": "high",
                    "explanation": f"Display suggests '{safe}' but link points to '{href_domain or href[:50]}'",
                })
                break
    return mismatches


def analyze_reply_to_mismatch(sender_email: str, reply_to_email: str) -> Optional[Dict]:
    """If Reply-To differs from From in a suspicious way (e.g. reply goes to attacker), return red flag."""
    if not reply_to_email or not sender_email or "@" not in reply_to_email:
        return None
    sender_domain = sender_email.split("@")[-1].lower()
    reply_domain = reply_to_email.split("@")[-1].lower()
    if sender_domain == reply_domain:
        return None
    # Free provider "sending as" brand but reply goes to different domain
    free = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"]
    if sender_domain in free and reply_domain not in free:
        return {"flag": "Reply-To domain mismatch", "severity": "high", "explanation": f"From domain '{sender_domain}' but Reply-To '{reply_domain}' — possible reply hijack"}
    if reply_domain in free and sender_domain not in free:
        return {"flag": "Reply-To redirect", "severity": "medium", "explanation": f"Reply-To points to '{reply_domain}' instead of sender domain"}
    return None


def analyze_url_heuristics(links: List[str]) -> List[Dict]:
    """
    Industry-standard URL heuristics: punycode/IDN homograph, excessive length,
    login/signin path with non-brand domain, hex-heavy path, double-slash abuse.
    """
    flags = []
    safe_domains = ["linkedin.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
                    "paypal.com", "github.com", "openai.com", "facebook.com", "netflix.com"]
    for link in links:
        if not link.startswith("http"):
            continue
        try:
            parsed = urlparse(link)
            netloc = (parsed.netloc or "").lower()
            path = (parsed.path or "").lower()
            full = link.lower()
        except Exception:
            continue
        # Punycode/IDN in hostname (xn-- indicates encoded unicode used for homograph attacks)
        if "xn--" in netloc:
            flags.append({"flag": "Punycode/IDN in URL", "severity": "high", "explanation": "Hostname uses punycode — possible homograph phishing"})
        # Very long URL (common in phishing redirect chains)
        if len(link) > 400:
            flags.append({"flag": "Suspiciously long URL", "severity": "medium", "explanation": "URL length suggests redirect chain or obfuscation"})
        # login/signin/sign-in in path but domain not a known brand
        if any(p in path for p in ["/login", "/signin", "/sign-in", "/verify", "/account", "/secure"]):
            if not any(sd in netloc for sd in safe_domains):
                flags.append({"flag": "Login-like URL from unknown domain", "severity": "high", "explanation": f"Path suggests login/verify but domain '{netloc[:40]}' is not a known brand"})
        # Hex-heavy path (obfuscation)
        if path and sum(c in "0123456789abcdef" for c in path) / max(len(path), 1) > 0.6:
            flags.append({"flag": "Hex-heavy URL path", "severity": "medium", "explanation": "Path appears obfuscated"})
    return flags[:5]  # Cap to avoid noise


def analyze_attachment_heuristics(attachment_details: List[Dict]) -> List[Dict]:
    """
    Industry-standard attachment checks: double extension, extension vs content-type mismatch.
    """
    flags = []
    dangerous_content_types = ("application/x-msdownload", "application/x-msdos-program",
                               "application/octet-stream", "application/x-executable",
                               "application/vnd.ms-excel.sheet.macroenabled", "application/vnd.ms-word.document.macroenabled")
    for item in attachment_details:
        filename = (item.get("filename") or "").lower()
        content_type = (item.get("content_type") or "").lower().split(";")[0].strip()
        # Double extension (e.g. document.pdf.exe, report.doc.scr)
        parts = filename.split(".")
        if len(parts) >= 3:
            ext1, ext2 = parts[-2], parts[-1]
            if ext2 in ("exe", "scr", "bat", "cmd", "ps1", "vbs", "js") and ext1 in ("pdf", "doc", "docx", "xls", "jpg", "png"):
                flags.append({"flag": "Double extension attachment", "severity": "critical", "explanation": f"Filename '{filename}' masks executable extension"})
        # Content-type suggests executable but extension is document
        if content_type in dangerous_content_types:
            if any(filename.endswith(e) for e in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png")):
                flags.append({"flag": "Content-Type vs extension mismatch", "severity": "critical", "explanation": f"Declared type '{content_type}' does not match extension"})
    return flags


def connect_imap(email_addr, password, imap_server=None, imap_port=993):
    """Connect to IMAP server. Auto-detects server from email domain."""
    if not imap_server:
        domain = email_addr.split("@")[-1].lower()
        imap_map = {
            "gmail.com": "imap.gmail.com",
            "googlemail.com": "imap.gmail.com",
            "outlook.com": "outlook.office365.com",
            "hotmail.com": "outlook.office365.com",
            "live.com": "outlook.office365.com",
            "yahoo.com": "imap.mail.yahoo.com",
            "icloud.com": "imap.mail.me.com",
            "me.com": "imap.mail.me.com",
        }
        imap_server = imap_map.get(domain, f"imap.{domain}")

    try:
        mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        mail.login(email_addr, password)
        return mail
    except Exception as e:
        print(f"[inbox_scanner] IMAP Connection Failed: {e}")
        return None


def fetch_inbox_emails(mail, folder="INBOX", count=10):
    """Fetch the latest emails from the inbox."""
    try:
        mail.select(folder)
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            return []

        email_ids = messages[0].split()
        latest_ids = email_ids[-count:]
        
        email_list = []
        for e_id in reversed(latest_ids):
            status, msg_data = mail.fetch(e_id, "(RFC822)")
            if status != "OK":
                continue
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    content = extract_email_content(msg)
                    content["id"] = e_id.decode()
                    email_list.append(content)
        
        return email_list
    except Exception as e:
        print(f"[inbox_scanner] Fetch Error: {e}")
        return []


# ─── Full-Spectrum AI Analysis ──────────────────────────────────────────────────

def _load_trained_model():
    """Load the trained scanner model from disk (once). Used when AI_PROVIDER=local."""
    global _trained_model_obj
    if _trained_model_obj is not None:
        return _trained_model_obj
    path = getattr(config, "TRAINED_MODEL_PATH", "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        import joblib
        _trained_model_obj = joblib.load(path)
        return _trained_model_obj
    except Exception as e:
        print(f"[inbox_scanner] Failed to load trained model: {e}")
        return None


def _call_trained_local_model(email_data: Dict) -> Optional[Dict]:
    """
    Run your trained model (no API key, no quota). Uses scanner_features + saved classifier.
    Set AI_PROVIDER=local and TRAINED_MODEL_PATH to the .joblib file from train_scanner_model.py.
    """
    try:
        from scanner_features import extract_features, get_feature_dim, FEATURE_VERSION
    except ImportError:
        return None
    obj = _load_trained_model()
    if not obj or "model" not in obj:
        return None
    # Require matching feature dimension (and optionally version) so old models aren't used with new features
    saved_dim = obj.get("feature_dim")
    current_dim = get_feature_dim()
    if saved_dim is not None and saved_dim != current_dim:
        print(f"[inbox_scanner] Trained model feature_dim={saved_dim} != current {current_dim}; retrain with train_scanner_model.py")
        return None
    if obj.get("feature_version") is not None and obj.get("feature_version") != FEATURE_VERSION:
        print(f"[inbox_scanner] Trained model feature_version={obj.get('feature_version')} != current {FEATURE_VERSION}; retrain recommended")
    model = obj["model"]
    features = extract_features(email_data)
    if features is None:
        return None
    import numpy as np
    X = np.array([features], dtype=np.float64)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        threat_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
    else:
        pred = model.predict(X)[0]
        threat_prob = 1.0 if pred == 1 else 0.0
    threat_score = max(0, min(100, round(threat_prob * 100, 1)))
    thr_phish, thr_susp, thr_spam = _get_thresholds()
    if threat_score >= thr_phish:
        verdict, risk_level = "PHISHING", "critical"
    elif threat_score >= thr_susp:
        verdict, risk_level = "SUSPICIOUS", "high"
    elif threat_score >= thr_spam:
        verdict, risk_level = "SPAM", "medium"
    else:
        verdict, risk_level = "SAFE", "low"
    return {
        "verdict": verdict,
        "confidence": 78,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "sub_scores": {"phishing": 0, "impersonation": 0, "scam": 0, "spam": 0, "malware": 0, "bec": 0, "social_engineering": 0},
        "summary": f"Trained local model: threat score {threat_score:.0f}/100.",
        "red_flags": [],
        "positive_signals": ["Scored by your trained model (no API)."] if threat_score < 30 else [],
        "category": "phishing" if verdict != "SAFE" else "legitimate",
        "recommendation": "Delete and report immediately" if risk_level == "critical" else ("Proceed with caution" if risk_level == "high" else "This email appears safe"),
        "ai_powered": True,
    }


def _call_custom_ai(email_data: Dict) -> Optional[Dict]:
    """
    Call your own AI model over HTTP. Your endpoint receives a JSON body and must return
    JSON with at least: verdict, threat_score; optionally summary, red_flags, category,
    risk_level, sub_scores, recommendation, confidence, positive_signals.
    Runs dynamically on every scan when AI_PROVIDER=custom and CUSTOM_AI_URL is set.
    """
    url = getattr(config, "CUSTOM_AI_URL", "").strip()
    if not url:
        return None
    timeout = getattr(config, "CUSTOM_AI_TIMEOUT", 30)
    api_key = getattr(config, "CUSTOM_AI_API_KEY", "").strip()
    body = email_data.get("body_text", "") or _strip_html(email_data.get("body_html", "") or "")
    payload = {
        "subject": email_data.get("subject", ""),
        "sender_name": email_data.get("sender_name", ""),
        "sender_email": email_data.get("sender_email", ""),
        "reply_to_email": email_data.get("reply_to_email", ""),
        "date": email_data.get("date", ""),
        "body_text": body[:5000],
        "links": email_data.get("links", [])[:20],
        "attachments": email_data.get("attachments", []),
        "auth_results": email_data.get("auth_results", {}),
        "list_unsubscribe": email_data.get("list_unsubscribe", ""),
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        print(f"[inbox_scanner] Custom AI request failed: {e}")
        return None
    try:
        out = json.loads(raw)
    except json.JSONDecodeError:
        return None
    # Normalize to scanner analysis format
    verdict = (out.get("verdict") or "SAFE").strip().upper()
    if verdict not in ("SAFE", "SUSPICIOUS", "PHISHING", "SPAM", "SCAM"):
        verdict = "SAFE"
    threat_score = max(0, min(100, float(out.get("threat_score", 0))))
    thr_phish, thr_susp, thr_spam = _get_thresholds()
    risk_level = out.get("risk_level") or (
        "critical" if threat_score >= thr_phish else "high" if threat_score >= thr_susp else "medium" if threat_score >= thr_spam else "low"
    )
    sub_scores = out.get("sub_scores") or {
        "phishing": 0, "impersonation": 0, "scam": 0, "spam": 0,
        "malware": 0, "bec": 0, "social_engineering": 0,
    }
    return {
        "verdict": verdict,
        "confidence": max(0, min(100, int(out.get("confidence", 75)))),
        "threat_score": threat_score,
        "risk_level": risk_level,
        "sub_scores": sub_scores,
        "summary": out.get("summary") or "Analyzed by custom AI model.",
        "red_flags": out.get("red_flags") or [],
        "positive_signals": out.get("positive_signals") or [],
        "category": out.get("category") or "legitimate",
        "recommendation": out.get("recommendation") or (
            "Delete and report immediately" if risk_level == "critical" else "This email appears safe"
        ),
        "ai_powered": True,
    }


def analyze_email_with_ai(email_data):
    """
    Adaptive AI threat analysis using Google Gemini.
    Detects ALL email threats: phishing, spear-phishing, BEC, 419 scams,
    tech support scams, malware, spam, invoice fraud, impersonation, and social engineering.
    """
    ttl = getattr(config, "ANALYSIS_CACHE_TTL_SEC", 0)
    cache_key = _analysis_cache_key(email_data) if ttl > 0 else None
    if ttl > 0 and cache_key and cache_key in _analysis_cache:
        cached, ts = _analysis_cache[cache_key]
        if (time.time() - ts) <= ttl:
            return cached
        del _analysis_cache[cache_key]

    # Your trained local model (no API key, no quota) — train with train_scanner_model.py
    if getattr(config, "AI_PROVIDER", "").lower() == "local":
        analysis = _call_trained_local_model(email_data)
        if analysis:
            result = _apply_adaptive_and_record(email_data, analysis)
            if ttl > 0 and cache_key:
                _analysis_cache[cache_key] = (result, time.time())
            return result
        # Model missing or failed: use rule-based
        result = _apply_adaptive_and_record(email_data, _fallback_analysis(email_data))
        if ttl > 0 and cache_key:
            _analysis_cache[cache_key] = (result, time.time())
        return result

    # Fallback: no external AI (rule-based + adaptive)
    use_fallback = (
        getattr(config, "AI_PROVIDER", "fallback").lower() == "fallback"
        or not getattr(config, "GEMINI_API_KEY", "")
    )
    if use_fallback and getattr(config, "AI_PROVIDER", "fallback").lower() != "custom":
        result = _apply_adaptive_and_record(email_data, _fallback_analysis(email_data))
        if ttl > 0 and cache_key:
            _analysis_cache[cache_key] = (result, time.time())
        return result

    # Your own AI model (custom HTTP endpoint) — runs dynamically per email
    if getattr(config, "AI_PROVIDER", "").lower() == "custom":
        custom_url = getattr(config, "CUSTOM_AI_URL", "").strip()
        if custom_url:
            try:
                analysis = _call_custom_ai(email_data)
                if analysis:
                    result = _apply_adaptive_and_record(email_data, analysis)
                    if ttl > 0 and cache_key:
                        _analysis_cache[cache_key] = (result, time.time())
                    return result
            except Exception as e:
                print(f"[inbox_scanner] Custom AI error: {e}")
                traceback.print_exc()
        # Custom but no URL or request failed: use rule-based
        result = _apply_adaptive_and_record(email_data, _fallback_analysis(email_data))
        if ttl > 0 and cache_key:
            _analysis_cache[cache_key] = (result, time.time())
        return result

    try:
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel(config.GEMINI_MODEL)

        links_str = "\n".join(email_data.get("links", [])[:15]) if email_data.get("links") else "No links"
        attachments_str = ", ".join(email_data.get("attachments", [])) if email_data.get("attachments") else "No attachments"
        body = email_data.get("body_text", "") or _strip_html(email_data.get("body_html", ""))

        sender_email_addr = email_data.get('sender_email', 'N/A')
        sender_domain = sender_email_addr.split('@')[-1].lower() if '@' in sender_email_addr else ''
        reply_to_addr = email_data.get('reply_to_email', '') or 'None'
        auth = email_data.get('auth_results') or {}
        auth_str = f"SPF={auth.get('spf', 'none')} DKIM={auth.get('dkim', 'none')} DMARC={auth.get('dmarc', 'none')}"

        prompt = f"""You are an elite cybersecurity SOC analyst performing real-time threat triage on live email traffic.
Classify this email with surgical precision. You MUST avoid false positives — marking safe emails as threats is a critical failure.

=== CRITICAL: LEGITIMATE EMAIL RECOGNITION (CHECK THIS FIRST!) ===
Before looking for threats, determine if this is a LEGITIMATE email:

TRUSTED SENDER DOMAINS — emails from these domains are almost always SAFE:
linkedin.com, facebookmail.com, google.com, youtube.com, microsoft.com,
apple.com, amazon.com, github.com, openai.com, email.openai.com,
netflix.com, twitter.com, x.com, instagram.com, spotify.com,
slack.com, zoom.us, dropbox.com, adobe.com, salesforce.com,
stripe.com, paypal.com, chase.com, bankofamerica.com, wellsfargo.com,
intuit.com, turbotax.intuit.com, uber.com, lyft.com, airbnb.com,
notion.so, figma.com, vercel.com, heroku.com, netlify.com,
aws.amazon.com, cloud.google.com, azure.microsoft.com

LEGITIMATE EMAIL PATTERNS (verdict = SAFE, threat_score 0-10):
- Connection requests, job alerts, post notifications from LinkedIn
- Privacy policy updates, account notifications from any trusted domain
- Order confirmations, shipping updates from e-commerce
- Newsletter/digest emails from services the user signed up for
- Password reset emails that the user likely requested
- Two-factor authentication codes
- Calendar invites from known services
- Social media notifications (likes, comments, follows, shares)
- Subscription confirmations, billing receipts from known services

KEY RULE: If sender domain matches a known service AND email content matches
that service's typical notifications, it is SAFE. Do NOT penalize:
- Emails containing "unsubscribe" (this is in ALL legitimate emails)
- Emails with tracking links from known services (e.g., linkedin.com click-tracking)
- Generic notification language from real services
- Marketing emails from legitimate brands the user subscribed to

=== DETECTION METHODS (use these in your analysis) ===
1. LOOKALIKE DOMAINS: Sender domain similar to a brand but not exact (e.g. gmail.co, paypa1.com) → IMPERSONATION/PHISHING.
2. REPLY-TO MISMATCH: If Reply-To header differs from From domain, replies may go to attacker → high severity red flag.
3. LINK DISPLAY MISMATCH: If link text shows a safe URL but href points elsewhere → PHISHING, critical.
4. DISPLAY NAME SPOOFING: Display name claims brand but From is free email (gmail, yahoo) → IMPERSONATION.
5. URGENCY + UNTRUSTED SENDER: "Act now", "suspended", "within 24 hours" from unknown sender → SOCIAL ENGINEERING.

=== THREAT CATEGORIES (only if NOT legitimate) ===
1. PHISHING: Credential harvesting, fake login pages, account verification scams
2. SPEAR PHISHING: Targeted attacks using specific names, roles, or internal info
3. BEC (Business Email Compromise): CEO fraud, invoice redirect, wire transfer requests
4. 419 / ADVANCE FEE SCAM: Inheritance, lottery winnings, investment schemes
5. TECH SUPPORT SCAM: Fake virus alerts, "device infected", call-this-number
6. MALWARE: Dangerous attachments (.exe .bat .scr macro-enabled docs)
7. SPAM: Unsolicited marketing from UNKNOWN senders, crypto pumps, adult content
8. INVOICE / PAYMENT FRAUD: Fake invoices, overdue notices, fake receipts
9. IMPERSONATION: Display name spoofing, look-alike domains, brand impersonation
10. SOCIAL ENGINEERING: Curiosity traps, fake leaked docs, fake emergencies

=== HOW TO DISTINGUISH SPAM FROM LEGITIMATE ===
- SPAM = unsolicited from unknown/untrusted senders with aggressive marketing
- LEGITIMATE = notifications, updates, newsletters from trusted brands/services
- If sender domain is a known company, it is NOT spam even if promotional
- LinkedIn notifications are NOT spam — they are service notifications
- OpenAI policy updates are NOT spam — they are account notifications

=== ANALYSIS RULES ===
- FIRST check if the sender domain is a known service. If YES, default to SAFE.
- Only override SAFE if there is STRONG evidence of compromise/spoofing.
- Flag MISMATCHES: Display name "PayPal Support" but email is random@gmail.com = PHISHING.
- SIMULATION MARKERS: "[PhishGuard AI Simulation]" or "simulated phishing" = PHISHING.
- Free email providers (gmail, outlook, yahoo) sending as brands = SUSPICIOUS/PHISHING.

=== EMAIL AUTHENTICATION (industry standard) ===
- Use Authentication-Results to weight spoofing. If SPF/DKIM/DMARC = fail or none and the sender claims to be a brand (e.g. PayPal, Microsoft), treat as strong evidence of IMPERSONATION/PHISHING.
- pass = legitimate; fail/none = possible spoof, especially if From domain claims to be a known brand.

=== SCORING RULES ===
- threat_score 0–100: 0–15 SAFE, 16–35 low risk, 36–55 SUSPICIOUS, 56–100 PHISHING/SCAM.
- Assign sub_scores (0–40 each) for each category that applies; most emails will have 0 for most.
- risk_level: "low" (SAFE), "medium" (spam), "high" (suspicious), "critical" (phishing/scam/malware).
- confidence: higher when evidence is clear (e.g. auth fail + brand claim = 90+).

=== EMAIL DATA ===
Subject: {email_data.get('subject', 'N/A')}
From (Display Name): {email_data.get('sender_name', 'N/A')}
From (Email): {sender_email_addr}
Reply-To: {reply_to_addr}
Sender Domain: {sender_domain}
Authentication-Results: {auth_str}
Date: {email_data.get('date', 'N/A')}

Body (first 2000 chars):
{body[:2000]}

Links:
{links_str}

Attachments:
{attachments_str}

=== RESPOND WITH ONLY VALID JSON ===
{{
    "verdict": "<SAFE|SUSPICIOUS|PHISHING|SPAM|SCAM>",
    "confidence": <0-100>,
    "threat_score": <0-100>,
    "risk_level": "<low|medium|high|critical>",
    "sub_scores": {{
        "phishing": <0-40>,
        "impersonation": <0-40>,
        "scam": <0-40>,
        "spam": <0-25>,
        "malware": <0-40>,
        "bec": <0-40>,
        "social_engineering": <0-30>
    }},
    "summary": "<1-2 sentence precise explanation>",
    "red_flags": [
        {{
            "flag": "<Short title>",
            "severity": "<low|medium|high|critical>",
            "explanation": "<Evidence-based reason>"
        }}
    ],
    "positive_signals": ["<Evidence of legitimacy>"],
    "category": "<legitimate|newsletter|transactional|phishing|spear_phishing|bec|scam|spam|malware|impersonation|social_engineering>",
    "recommendation": "<Actionable advice>"
}}"""

        response = model.generate_content(prompt)
        text = response.text.strip()

        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            text = text.rsplit("```", 1)[0].strip()

        analysis = json.loads(text)
        analysis["ai_powered"] = True
        # Ensure scoring fields exist for consistent downstream use
        if "risk_level" not in analysis:
            thr_phish, thr_susp, thr_spam = _get_thresholds()
            sc = analysis.get("threat_score", 0)
            analysis["risk_level"] = (
                "critical" if sc >= thr_phish else "high" if sc >= thr_susp else "medium" if sc >= thr_spam else "low"
            )
        if "sub_scores" not in analysis:
            analysis["sub_scores"] = {
                "phishing": 0, "impersonation": 0, "scam": 0, "spam": 0,
                "malware": 0, "bec": 0, "social_engineering": 0,
            }
        thr_phish, thr_susp, thr_spam = _get_thresholds()
        if analysis.get("risk_level") is None and "threat_score" in analysis:
            sc = analysis["threat_score"]
            analysis["risk_level"] = "critical" if sc >= thr_phish else "high" if sc >= thr_susp else "medium" if sc >= thr_spam else "low"
        result = _apply_adaptive_and_record(email_data, analysis)
        if ttl > 0 and cache_key:
            _analysis_cache[cache_key] = (result, time.time())
        return result

    except Exception as e:
        print(f"[inbox_scanner] Gemini analysis error: {e}")
        traceback.print_exc()
        result = _apply_adaptive_and_record(email_data, _fallback_analysis(email_data))
        if ttl > 0 and cache_key:
            _analysis_cache[cache_key] = (result, time.time())
        return result


def _strip_html(html_str):
    """Remove HTML tags from a string."""
    return re.sub('<[^<]+?>', '', html_str)


def _get_thresholds() -> Tuple[int, int, int]:
    """Return (phishing_min, suspicious_min, spam_min). Dynamic: from scanner_config.json then env."""
    try:
        from scanner_config_loader import get_thresholds as _get_dynamic_thresholds
        return _get_dynamic_thresholds(config)
    except ImportError:
        return (
            getattr(config, "SCANNER_THRESHOLD_PHISHING", 65),
            getattr(config, "SCANNER_THRESHOLD_SUSPICIOUS", 40),
            getattr(config, "SCANNER_THRESHOLD_SPAM", 22),
        )


def _analysis_cache_key(email_data: Dict) -> str:
    """Stable key for caching analysis by email identity."""
    s = (email_data.get("subject") or "") + "\n" + (email_data.get("sender_email") or "")
    links = email_data.get("links") or []
    s += "\n" + (links[0] if links else "")
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _apply_adaptive_and_record(email_data: Dict, analysis: Dict) -> Dict:
    """
    Apply dynamic learning: adjust threat_score from domain reputation, similar-past prior,
    and optional online classifier; then persist this scan for future learning.
    """
    if not _ADAPTIVE_AVAILABLE:
        return analysis
    try:
        delta_info = get_adaptive_delta(email_data)
        combined = delta_info.get("combined_delta", 0)
        base_score = float(analysis.get("threat_score", 0))
        learned_score = delta_info.get("learned_score")
        learned_delta = delta_info.get("learned_delta", 0)
        # Dynamic model: blend static (or local .joblib) score with online learner when available
        if learned_score is not None:
            blended_base = 0.7 * base_score + 0.3 * learned_score
            combined_no_learned = combined - learned_delta
            new_score = max(0, min(100, blended_base + combined_no_learned))
        else:
            new_score = max(0, min(100, base_score + combined))
        # Trust = domain score first (reputation from history), then allowlist only when no history
        sender_domain = (email_data.get("sender_email") or "").split("@")[-1].lower()
        domain_safe = delta_info.get("domain_safe_count", 0)
        domain_threat = delta_info.get("domain_threat_count", 0)
        domain_delta = delta_info.get("domain_delta", 0)
        total_domain_scans = domain_safe + domain_threat
        # Strong-safe reputation: mostly seen as safe (delta <= -12) and enough history (3+ safe)
        reputation_trusted = total_domain_scans >= 3 and domain_safe >= 2 and domain_delta <= -10
        allowlist_trusted = bool(
            threat_intel_check_domain and sender_domain and threat_intel_check_domain(sender_domain) == "allowlist"
        )
        if reputation_trusted or allowlist_trusted:
            cap = 22  # below typical spam threshold so verdict stays SAFE
            if new_score > cap:
                reason = "domain score (reputation)" if reputation_trusted else "allowlist"
                analysis["summary"] = f"Trusted by {reason} ({sender_domain}); score capped to {cap}. Content/attachments checked. Original: {new_score:.0f}/100."
                new_score = min(new_score, cap)
        analysis["threat_score"] = round(new_score, 1)
        # Re-derive verdict, risk_level, and recommendation from adjusted score (configurable thresholds)
        thr_phish, thr_susp, thr_spam = _get_thresholds()
        if new_score >= thr_phish:
            analysis["verdict"], analysis["risk_level"] = "PHISHING", "critical"
            analysis["recommendation"] = "Delete and report immediately"
        elif new_score >= thr_susp:
            analysis["verdict"], analysis["risk_level"] = "SUSPICIOUS", "high"
            analysis["recommendation"] = "Do not click links or open attachments; verify sender via another channel"
        elif new_score >= thr_spam:
            analysis["verdict"], analysis["risk_level"] = "SPAM", "medium"
            analysis["recommendation"] = "Treat as unsolicited; avoid engaging"
        else:
            analysis["verdict"], analysis["risk_level"] = "SAFE", "low"
            analysis["recommendation"] = "This email appears safe"
        analysis["adaptive"] = {
            "email_hash": delta_info.get("email_hash"),
            "combined_delta": delta_info.get("combined_delta"),
            "domain_delta": delta_info.get("domain_delta"),
            "domain_safe_count": delta_info.get("domain_safe_count"),
            "domain_threat_count": delta_info.get("domain_threat_count"),
            "similar_prior": delta_info.get("similar_prior"),
            "similar_count": delta_info.get("similar_count"),
            "learned_score": delta_info.get("learned_score"),
            "explanation": delta_info.get("explanation"),
        }
        record_scan(email_data, analysis)
    except Exception as e:
        print(f"[inbox_scanner] Adaptive layer error: {e}")
        traceback.print_exc()
    return analysis


# ─── Robust Fallback Analysis ───────────────────────────────────────────────────

def _score_from_flags(red_flags: List[Dict], category_filter: Optional[str] = None) -> int:
    """Sum severity-weighted score from red_flags. Optionally only count flags whose explanation matches a category keyword."""
    total = 0
    for f in red_flags:
        sev = f.get("severity", "low")
        points = SEVERITY_WEIGHTS.get(sev, SEVERITY_WEIGHTS["low"])
        if category_filter and category_filter not in (f.get("flag") or "").lower():
            continue
        total += points
    return total


def _fallback_analysis(email_data: Dict) -> Dict:
    """
    Multi-category rule-based analysis with severity-weighted scoring and sub-scores.
    Covers phishing, BEC, spam, scams, impersonation, malware, and social engineering.
    Uses lookalike domain, Reply-To mismatch, and link-display mismatch detection.
    """
    body = (email_data.get("body_text", "") or _strip_html(email_data.get("body_html", ""))).lower()
    sender_email = email_data.get("sender_email", "").lower()
    sender_name = email_data.get("sender_name", "").lower()
    subject = email_data.get("subject", "").lower()
    links = email_data.get("links", [])
    link_display_pairs = email_data.get("link_display_pairs", [])
    reply_to_email = (email_data.get("reply_to_email") or "").strip().lower()
    auth_results = email_data.get("auth_results") or {}
    attachment_details = email_data.get("attachment_details") or []
    if not attachment_details and email_data.get("attachments"):
        attachment_details = [{"filename": f, "content_type": ""} for f in email_data["attachments"]]

    red_flags: List[Dict] = []
    positive_signals: List[str] = []
    detected_category = "legitimate"

    # Per-category score caps to avoid one vector dominating (then summed for threat_score)
    sub_scores = {
        "phishing": 0,
        "impersonation": 0,
        "scam": 0,
        "spam": 0,
        "malware": 0,
        "bec": 0,
        "social_engineering": 0,
    }
    category_caps = {"phishing": 45, "impersonation": 45, "scam": 45, "spam": 25, "malware": 45, "bec": 40, "social_engineering": 30}

    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    free_providers = ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "aol.com", "icloud.com", "ymail.com", "protonmail.com"]

    trusted_domains = [
        "linkedin.com", "facebookmail.com", "facebook.com", "twitter.com", "x.com",
        "instagram.com", "pinterest.com", "reddit.com", "tiktok.com",
        "google.com", "microsoft.com", "apple.com", "amazon.com", "amazon.co.uk",
        "github.com", "gitlab.com", "bitbucket.org", "vercel.com", "netlify.com",
        "heroku.com", "digitalocean.com", "cloudflare.com", "render.com",
        "openai.com", "email.openai.com", "anthropic.com", "notion.so",
        "figma.com", "canva.com", "slack.com", "zoom.us", "zoom.com",
        "atlassian.com", "trello.com", "asana.com", "monday.com",
        "netflix.com", "spotify.com", "hulu.com", "disneyplus.com", "youtube.com",
        "shopify.com", "ebay.com", "etsy.com", "paypal.com", "stripe.com", "venmo.com",
        "coursera.org", "udemy.com", "edx.org",
        "uber.com", "lyft.com", "airbnb.com", "booking.com",
        "discord.com", "discordapp.com", "telegram.org", "whatsapp.com",
        "auth0.com", "okta.com", "1password.com", "lastpass.com",
        "adobe.com", "behance.net", "dribbble.com",
        "dropbox.com", "box.com", "evernote.com",
        "salesforce.com", "hubspot.com", "mailchimp.com", "constantcontact.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "capitalone.com", "americanexpress.com", "discover.com",
        "intuit.com", "turbotax.intuit.com",
    ]

    is_trusted_sender = any(
        sender_domain == td or sender_domain.endswith("." + td) for td in trusted_domains
    )
    if is_trusted_sender:
        positive_signals.append(f"Verified enterprise sender ({sender_domain})")

    def _add_flag(flag: Dict, category_key: str) -> None:
        red_flags.append(flag)
        sev = flag.get("severity", "low")
        pts = min(SEVERITY_WEIGHTS.get(sev, 5), category_caps.get(category_key, 40) - sub_scores.get(category_key, 0))
        sub_scores[category_key] = min(sub_scores.get(category_key, 0) + pts, category_caps.get(category_key, 40))

    # 0. Threat intel blocklist/allowlist (industry standard)
    if threat_intel_check_domain:
        intel = threat_intel_check_domain(sender_domain)
        if intel == "blocklist":
            _add_flag({"flag": "Sender on blocklist", "severity": "critical", "explanation": f"Domain '{sender_domain}' is on the threat blocklist"}, "phishing")
            detected_category = "phishing"
            is_trusted_sender = False  # blocklist overrides trusted
        elif intel == "allowlist":
            is_trusted_sender = True
            positive_signals.append(f"Sender on allowlist ({sender_domain})")

    # 0a. Email authentication (SPF/DKIM/DMARC) — industry standard
    spf, dkim, dmarc = auth_results.get("spf", "none"), auth_results.get("dkim", "none"), auth_results.get("dmarc", "none")
    auth_fail = spf == "fail" or dkim == "fail" or dmarc == "fail"
    auth_none = spf == "none" and dkim == "none" and dmarc == "none"
    if auth_fail and not is_trusted_sender:
        _add_flag({"flag": "Email authentication failed", "severity": "critical", "explanation": f"SPF={spf} DKIM={dkim} DMARC={dmarc} — possible spoofing"}, "impersonation")
        if detected_category == "legitimate":
            detected_category = "impersonation"
    elif auth_fail and is_trusted_sender:
        _add_flag({"flag": "Authentication failed for trusted domain", "severity": "high", "explanation": f"SPF={spf} DKIM={dkim} DMARC={dmarc}"}, "phishing")

    # 0b. URL heuristics (punycode, long URL, login path from unknown domain)
    for uflag in analyze_url_heuristics(links):
        red_flags.append(uflag)
        pts = SEVERITY_WEIGHTS.get(uflag.get("severity", "medium"), 12)
        sub_scores["phishing"] = min(sub_scores["phishing"] + pts, category_caps["phishing"])

    # 0c. Attachment heuristics (double extension, content-type mismatch)
    for aflag in analyze_attachment_heuristics(attachment_details):
        red_flags.append(aflag)
        pts = SEVERITY_WEIGHTS.get(aflag.get("severity", "critical"), 40)
        sub_scores["malware"] = min(sub_scores["malware"] + pts, category_caps["malware"])
        if detected_category == "legitimate":
            detected_category = "malware"

    # 0. Lookalike domain (typosquatting)
    lookalike, matched_brand = is_lookalike_domain(sender_domain)
    if lookalike and not is_trusted_sender:
        _add_flag({
            "flag": "Lookalike domain",
            "severity": "critical",
            "explanation": f"Domain resembles '{matched_brand}' but is not the official domain",
        }, "impersonation")
        if detected_category == "legitimate":
            detected_category = "impersonation"

    # 0b. Reply-To mismatch (reply hijacking)
    reply_mismatch = analyze_reply_to_mismatch(sender_email, reply_to_email or email_data.get("reply_to_email", ""))
    if reply_mismatch:
        red_flags.append(reply_mismatch)
        pts = SEVERITY_WEIGHTS.get(reply_mismatch.get("severity", "medium"), 12)
        sub_scores["phishing"] = min(sub_scores["phishing"] + pts, category_caps["phishing"])

    # 0c. Link display vs href mismatch (deceptive link)
    for mismatch in analyze_link_display_mismatch(link_display_pairs):
        red_flags.append(mismatch)
        pts = SEVERITY_WEIGHTS.get(mismatch.get("severity", "high"), 22)
        sub_scores["phishing"] = min(sub_scores["phishing"] + pts, category_caps["phishing"])
        if detected_category == "legitimate":
            detected_category = "phishing"

    # 1. PhishGuard simulation (always critical)
    if "phishguard" in body or "simulated phishing" in body or "phishguard ai" in body:
        _add_flag({"flag": "Simulated Phishing Test", "severity": "critical", "explanation": "Contains PhishGuard AI simulation markers"}, "phishing")
        detected_category = "phishing"

    # 2. Display name spoofing (brand name + free provider)
    brand_keywords = ["apple", "google", "microsoft", "paypal", "amazon", "netflix", "bank", "support", "security", "admin", "payroll", "chase", "citibank", "wells fargo", "irs", "tax"]
    if not is_trusted_sender:
        for brand in brand_keywords:
            if brand in sender_name and sender_domain in free_providers:
                _add_flag({"flag": "Display name spoofing", "severity": "critical", "explanation": f"Claims '{brand}' but uses free provider '{sender_domain}'"}, "impersonation")
                detected_category = "impersonation"
                break

    # 3–8. Rule-based detection (dynamic: builtin + scanner_rules.json)
    try:
        from scanner_config_loader import get_dynamic_rules
        rules = get_dynamic_rules()
    except ImportError:
        rules = {
            "cred_patterns": ["verify your account", "confirm your identity", "update your password", "enter your credentials", "click here to verify", "validate your login", "sign in to confirm", "re-enter your password", "account verification required"],
            "urgency": ["act now", "suspended", "unauthorized", "terminated", "within 24 hours", "within 2 hours", "failure to comply", "last warning", "final notice", "immediately", "urgent action required"],
            "bec_patterns": ["wire transfer", "new bank account", "change of payment details", "urgent wire", "ceo request", "executive request", "vendor payment", "update our records", "send payment to", "as per our ceo", "confidential request"],
            "scam_patterns": ["million dollars", "inheritance", "unclaimed funds", "lottery winner", "congratulations you have won", "western union", "bitcoin opportunity", "crypto investment", "double your money", "guaranteed return", "beneficiary", "next of kin", "prince", "nigerian", "offshore account"],
            "tech_support": ["your device is infected", "call this number", "microsoft support", "apple support", "virus detected", "remote access", "tech support callback", "your computer has been compromised"],
            "spam_patterns": ["weight loss", "enlargement", "limited time offer", "buy now", "discount code", "no obligation", "act now and save", "you have been selected", "click below to claim", "100% free", "earn money fast", "work from home opportunity"],
        }
    cred_patterns = rules.get("cred_patterns", [])
    found_cred = [p for p in cred_patterns if p in body]
    if found_cred and not is_trusted_sender:
        _add_flag({"flag": "Credential harvesting", "severity": "high", "explanation": f"Requests: '{found_cred[0]}'"}, "phishing")
        if detected_category == "legitimate":
            detected_category = "phishing"

    urgency = rules.get("urgency", [])
    found_urgency = [w for w in urgency if w in subject or w in body]
    if found_urgency and not is_trusted_sender:
        _add_flag({"flag": "Urgency / pressure tactics", "severity": "high", "explanation": f"Pressure words: {', '.join(found_urgency[:3])}"}, "social_engineering")

    bec_patterns = rules.get("bec_patterns", [])
    found_bec = [p for p in bec_patterns if p in body]
    if found_bec and not is_trusted_sender:
        _add_flag({"flag": "BEC / wire fraud", "severity": "critical", "explanation": f"BEC-style language: '{found_bec[0]}'"}, "bec")
        if detected_category == "legitimate":
            detected_category = "bec"

    scam_patterns = rules.get("scam_patterns", [])
    found_scam = [p for p in scam_patterns if p in body]
    if found_scam:
        _add_flag({"flag": "Financial scam", "severity": "critical", "explanation": f"Classic scam language: '{found_scam[0]}'"}, "scam")
        detected_category = "scam"

    tech_support = rules.get("tech_support", [])
    found_tech = [p for p in tech_support if p in body or p in subject]
    if found_tech and not is_trusted_sender:
        _add_flag({"flag": "Tech support scam", "severity": "high", "explanation": f"Tech support scam indicator: '{found_tech[0]}'"}, "scam")

    if not is_trusted_sender:
        spam_patterns = rules.get("spam_patterns", [])
        found_spam = [p for p in spam_patterns if p in body]
        if len(found_spam) >= 2:
            _add_flag({"flag": "Spam content", "severity": "medium", "explanation": f"Spam indicators: {', '.join(found_spam[:3])}"}, "spam")
            if detected_category == "legitimate":
                detected_category = "spam"

    # 9. Suspicious links (shorteners, IP, tunnels)
    safe_link_domains = ["linkedin.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "openai.com", "facebook.com", "twitter.com", "instagram.com", "youtube.com", "netflix.com", "spotify.com", "slack.com", "zoom.us", "dropbox.com", "adobe.com", "paypal.com", "stripe.com", "vercel.com"]
    suspicious_links = []
    for link in links:
        l = link.lower()
        if any(safe_d in l for safe_d in safe_link_domains):
            continue
        if any(x in l for x in ["bit.ly", "tinyurl", "goo.gl", "is.gd", "rb.gy", "cutt.ly"]):
            suspicious_links.append("URL shortener")
        elif re.match(r'https?://\d+\.\d+\.\d+\.\d+', l):
            suspicious_links.append("IP-based URL")
        elif any(x in l for x in ["ngrok", "loclx", "serveo", "localtunnel"]):
            suspicious_links.append("Tunnel/proxy")
    if suspicious_links:
        _add_flag({"flag": "Suspicious links", "severity": "high", "explanation": f"Found: {', '.join(set(suspicious_links))}"}, "phishing")

    # 10. Dangerous attachments
    danger_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".docm", ".xlsm", ".iso", ".img", ".jar", ".wsf"]
    bad_attachments = [a for a in email_data.get("attachments", []) if any(a.lower().endswith(e) for e in danger_exts)]
    if bad_attachments:
        _add_flag({"flag": "Dangerous attachment", "severity": "critical", "explanation": f"Risky file type: {', '.join(bad_attachments)}"}, "malware")
        if detected_category == "legitimate":
            detected_category = "malware"

    # ── Aggregate threat_score from sub-scores (weighted sum, then cap)
    threat_score = sum(sub_scores.values())
    has_critical_flag = any(f.get("severity") == "critical" for f in red_flags)

    if is_trusted_sender and not has_critical_flag:
        threat_score = max(0, threat_score - 35)
        positive_signals.append("Trusted sender — score reduced")
        if threat_score < 15:
            detected_category = "legitimate"
    elif is_trusted_sender:
        positive_signals.append("Sender is from a known domain but content has critical flags")

    if not red_flags:
        positive_signals.append("No suspicious indicators detected")
    if is_trusted_sender and "unsubscribe" in body:
        positive_signals.append("Contains standard unsubscribe link (normal for legitimate emails)")
    # List-Unsubscribe header: strong signal for legitimate bulk/marketing (RFC 8058)
    list_unsub = (email_data.get("list_unsubscribe") or "").strip()
    if list_unsub and not has_critical_flag and threat_score < 50:
        positive_signals.append("List-Unsubscribe header present (typical of legitimate mailing lists)")

    threat_score = max(0, min(100, threat_score))

    # Confidence: higher when many signals agree or one critical; lower when single weak signal
    num_critical = sum(1 for f in red_flags if f.get("severity") == "critical")
    num_high = sum(1 for f in red_flags if f.get("severity") == "high")
    if is_trusted_sender and threat_score < 20:
        confidence = 92
    elif num_critical >= 1:
        confidence = 85
    elif num_high >= 2 or (num_high >= 1 and len(red_flags) >= 2):
        confidence = 80
    elif red_flags:
        confidence = 70
    else:
        confidence = 78

    # Verdict and risk level (configurable thresholds)
    thr_phish, thr_susp, thr_spam = _get_thresholds()
    if threat_score >= thr_phish:
        verdict = "PHISHING"
        risk_level = "critical"
    elif threat_score >= thr_susp:
        verdict = "SUSPICIOUS"
        risk_level = "high"
    elif threat_score >= thr_spam:
        verdict = "SPAM"
        risk_level = "medium"
    else:
        verdict = "SAFE"
        risk_level = "low"

    summary = f"Detected {len(red_flags)} threat indicator(s). " + (red_flags[0]["explanation"] if red_flags else "No significant threats found.")
    recommendation = (
        "Delete and report immediately" if risk_level == "critical" else
        "Do not click links or open attachments; verify sender via another channel" if risk_level == "high" else
        "Treat as unsolicited; avoid engaging" if risk_level == "medium" else
        "This email appears safe"
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "sub_scores": sub_scores,
        "summary": summary,
        "red_flags": red_flags,
        "positive_signals": positive_signals if positive_signals else ["No specific safe signals"],
        "category": detected_category,
        "recommendation": recommendation,
        "ai_powered": False,
    }
