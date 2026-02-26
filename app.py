"""
AI-Driven Parameterized Phishing Email Generator
Flask Application — Main Entry Point
"""

import json
import sqlite3
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify

import config
from indicator_engine import (
    generate_attachment,
    generate_url,
    build_indicator_report,
    validate_indicators,
)
from email_generator import generate_email
from email_sender import send_email


def _inbox_scanner():
    """Lazy import so app can start on Vercel even if scanner deps are slow or fail."""
    from inbox_scanner import connect_imap, fetch_inbox_emails, analyze_email_with_ai
    return connect_imap, fetch_inbox_emails, analyze_email_with_ai

try:
    from adaptive_learning import submit_feedback as adaptive_submit_feedback
except ImportError:
    adaptive_submit_feedback = None

try:
    from scanner_evaluation import evaluate as scanner_evaluate
except ImportError:
    scanner_evaluate = None

try:
    from threat_intel import (
        get_lists as threat_intel_get_lists,
        get_blocklist_allowlist_counts,
        add_to_blocklist as threat_intel_add_blocklist,
        add_to_allowlist as threat_intel_add_allowlist,
        add_to_allowlist_bulk as threat_intel_add_allowlist_bulk,
        remove_from_blocklist as threat_intel_remove_blocklist,
        remove_from_allowlist as threat_intel_remove_allowlist,
        reload_lists as threat_intel_reload,
    )
except ImportError:
    threat_intel_get_lists = None
    get_blocklist_allowlist_counts = None
    threat_intel_add_blocklist = None
    threat_intel_add_allowlist = None
    threat_intel_add_allowlist_bulk = None
    threat_intel_remove_blocklist = None
    threat_intel_remove_allowlist = None
    threat_intel_reload = None

_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    static_folder=os.path.join(_dir, "static"),
    template_folder=os.path.join(_dir, "templates"),
)
app.secret_key = config.SECRET_KEY


# ─── Database Setup ─────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            emotional_trigger TEXT,
            context TEXT,
            attachment_type TEXT,
            link_type TEXT,
            subject TEXT,
            body_html TEXT,
            sender_name TEXT,
            sender_email TEXT,
            attachment_filename TEXT,
            suspicious_url TEXT,
            display_text TEXT,
            indicators_json TEXT
        )
    """)
    conn.commit()
    conn.close()


try:
    init_db()
except Exception as e:
    print(f"[app] DB init warning (non-fatal): {e}")


# ─── Error handler (avoid 500 crash on Vercel) ──────────────────────────────────

@app.errorhandler(Exception)
def handle_error(e):
    """Return JSON 500 instead of crashing the serverless function."""
    print(f"[app] Unhandled error: {e}")
    return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/health")
def api_health():
    """Lightweight health check; does not load scanner or DB."""
    return jsonify({"ok": True, "service": "PhishGuard AI"})


# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate a parameterized phishing email."""
    try:
        data = request.get_json()

        emotional_trigger = data.get("emotional_trigger", "urgency")
        context_dept = data.get("context", "IT")
        attachment_type = data.get("attachment_type", "none")
        link_type = data.get("link_type", "none")

        # Step 1: Generate indicators via the Injection Engine
        attachment_filename, attachment_desc = generate_attachment(attachment_type, context_dept)
        suspicious_url, display_text, url_desc = generate_url(link_type, context_dept)

        # Step 2: Build params for the AI generator
        gen_params = {
            "emotional_trigger": emotional_trigger,
            "context": context_dept,
            "attachment_type": attachment_type,
            "attachment_filename": attachment_filename,
            "attachment_description": attachment_desc,
            "link_type": link_type,
            "suspicious_url": suspicious_url,
            "display_text": display_text,
            "url_description": url_desc,
        }

        # Step 3: Generate email content
        email_data = generate_email(gen_params)

        # Step 4: Build indicator report for red-flag highlighting
        indicators = build_indicator_report(gen_params)

        # Step 5: Validate indicators
        validation = validate_indicators(
            email_data.get("body_html", ""),
            gen_params,
        )

        # Step 6: Save to history
        conn = get_db()
        conn.execute(
            """INSERT INTO email_history
               (created_at, emotional_trigger, context, attachment_type, link_type,
                subject, body_html, sender_name, sender_email,
                attachment_filename, suspicious_url, display_text, indicators_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                emotional_trigger,
                context_dept,
                attachment_type,
                link_type,
                email_data.get("subject", ""),
                email_data.get("body_html", ""),
                email_data.get("sender_name", ""),
                email_data.get("sender_email", ""),
                attachment_filename or "",
                suspicious_url or "",
                display_text or "",
                json.dumps(indicators),
            ),
        )
        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "email": email_data,
            "indicators": indicators,
            "validation": validation,
            "params": {
                "emotional_trigger": emotional_trigger,
                "context": context_dept,
                "attachment_type": attachment_type,
                "link_type": link_type,
                "attachment_filename": attachment_filename,
                "suspicious_url": suspicious_url,
                "display_text": display_text,
            },
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history")
def api_history():
    """Return generation history."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM email_history ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "created_at": row["created_at"],
            "emotional_trigger": row["emotional_trigger"],
            "context": row["context"],
            "attachment_type": row["attachment_type"],
            "link_type": row["link_type"],
            "subject": row["subject"],
            "body_html": row["body_html"],
            "sender_name": row["sender_name"],
            "sender_email": row["sender_email"],
            "attachment_filename": row["attachment_filename"],
            "suspicious_url": row["suspicious_url"],
            "indicators": json.loads(row["indicators_json"]) if row["indicators_json"] else [],
        })

    return jsonify({"success": True, "history": history})


@app.route("/api/export/<int:email_id>")
def api_export(email_id):
    """Export a generated email as standalone HTML."""
    conn = get_db()
    row = conn.execute("SELECT * FROM email_history WHERE id = ?", (email_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Email not found"}), 404

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{row['subject']}</title>
<style>body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 20px; }}</style>
</head>
<body>
<div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
<strong>From:</strong> {row['sender_name']} &lt;{row['sender_email']}&gt;<br>
<strong>Subject:</strong> {row['subject']}<br>
<strong>Date:</strong> {row['created_at']}
</div>
{row['body_html']}
</body>
</html>"""

    return html, 200, {"Content-Type": "text/html"}


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """AI-powered phishing email analyzer — uses Gemini to provide detailed threat analysis."""
    try:
        data = request.get_json()
        email_subject = data.get("subject", "")
        email_body = data.get("body_html", "")
        sender_email = data.get("sender_email", "")

        if not email_body:
            return jsonify({"success": False, "error": "No email content to analyze"}), 400

        # Try AI-powered analysis first
        provider = config.AI_PROVIDER
        if provider == "gemini" and config.GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=config.GEMINI_API_KEY)
                model = genai.GenerativeModel(config.GEMINI_MODEL)

                prompt = f"""You are an expert cybersecurity analyst specializing in phishing email detection.

Analyze this email and provide a structured threat assessment.

**Email Subject:** {email_subject}
**Sender:** {sender_email}
**Email Body (HTML):** {email_body}

Respond with ONLY valid JSON in this exact format:
{{
    "threat_score": <number 1-100>,
    "threat_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "summary": "<1-2 sentence summary of the threat>",
    "red_flags": [
        {{
            "flag": "<name of the red flag>",
            "description": "<detailed explanation>",
            "severity": "<low|medium|high|critical>"
        }}
    ],
    "social_engineering_tactics": ["<tactic 1>", "<tactic 2>"],
    "recommendation": "<what an employee should do if they receive this>"
}}"""

                response = model.generate_content(prompt)
                text = response.text.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1]
                    text = text.rsplit("```", 1)[0]
                analysis = json.loads(text)

                return jsonify({
                    "success": True,
                    "analysis": analysis,
                    "powered_by": "Google Gemini AI",
                })

            except Exception as e:
                print(f"[analyzer] Gemini error: {e}, falling back to rule-based")

        # Rule-based fallback analysis
        import re
        body_text = re.sub(r'<[^>]+>', '', email_body).lower()

        red_flags = []
        threat_score = 20  # base

        # Check for urgency words
        urgency_words = ["urgent", "immediately", "expires", "deadline", "within 24 hours", "act now", "time-sensitive", "asap"]
        found_urgency = [w for w in urgency_words if w in body_text]
        if found_urgency:
            red_flags.append({
                "flag": "Urgency Language",
                "description": f"Email uses high-pressure words: {', '.join(found_urgency)}. Attackers create false urgency to bypass critical thinking.",
                "severity": "high",
            })
            threat_score += 15

        # Check for authority impersonation
        authority_words = ["ceo", "cfo", "director", "administrator", "compliance", "mandatory", "required by policy", "chief"]
        found_authority = [w for w in authority_words if w in body_text]
        if found_authority:
            red_flags.append({
                "flag": "Authority Impersonation",
                "description": f"Email impersonates authority figures using terms: {', '.join(found_authority)}.",
                "severity": "high",
            })
            threat_score += 15

        # Check for fear tactics
        fear_words = ["suspended", "terminated", "breach", "compromised", "unauthorized", "violation", "permanently"]
        found_fear = [w for w in fear_words if w in body_text]
        if found_fear:
            red_flags.append({
                "flag": "Fear-Based Manipulation",
                "description": f"Email uses threatening language: {', '.join(found_fear)}.",
                "severity": "critical",
            })
            threat_score += 20

        # Check for suspicious links
        links = re.findall(r'href=["\']([^"\']+)["\']', email_body)
        suspicious_links = [l for l in links if any(x in l for x in ["http://", "bit.ly", "tinyurl", "192.168", "10.0.0", "172.16"])]
        if suspicious_links:
            red_flags.append({
                "flag": "Suspicious Links Detected",
                "description": f"Found {len(suspicious_links)} suspicious link(s) using IP addresses, URL shorteners, or unencrypted HTTP.",
                "severity": "critical",
            })
            threat_score += 20

        # Check for suspicious file references
        suspicious_exts = [".exe", ".scr", ".bat", ".com", ".docm", ".xlsm", ".zip", ".rar", ".7z"]
        found_files = [ext for ext in suspicious_exts if ext in body_text]
        if found_files:
            red_flags.append({
                "flag": "Suspicious Attachments",
                "description": f"Email references files with dangerous extensions: {', '.join(found_files)}.",
                "severity": "critical",
            })
            threat_score += 15

        # Check for reward/too-good-to-be-true
        reward_words = ["bonus", "gift card", "reward", "congratulations", "prize", "promotion", "exclusive"]
        found_reward = [w for w in reward_words if w in body_text]
        if found_reward:
            red_flags.append({
                "flag": "Reward-Based Lure",
                "description": f"Email promises enticing rewards: {', '.join(found_reward)}. Common social engineering tactic.",
                "severity": "medium",
            })
            threat_score += 10

        # Spoofed sender check
        if sender_email and "@company.com" in sender_email:
            red_flags.append({
                "flag": "Potentially Spoofed Sender",
                "description": f"Sender '{sender_email}' uses a generic company domain that could be spoofed.",
                "severity": "medium",
            })
            threat_score += 5

        threat_score = min(threat_score, 100)

        if threat_score >= 80:
            threat_level = "CRITICAL"
        elif threat_score >= 60:
            threat_level = "HIGH"
        elif threat_score >= 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        tactics = []
        if found_urgency:
            tactics.append("False Urgency")
        if found_authority:
            tactics.append("Authority Impersonation")
        if found_fear:
            tactics.append("Fear Induction")
        if found_reward:
            tactics.append("Reward-Based Luring")
        if suspicious_links:
            tactics.append("Credential Harvesting via Fake Links")
        if found_files:
            tactics.append("Malware Delivery via Attachments")

        analysis = {
            "threat_score": threat_score,
            "threat_level": threat_level,
            "summary": f"This email exhibits {len(red_flags)} phishing indicator(s) with a threat score of {threat_score}/100. "
                       f"Primary tactics include {', '.join(tactics[:3]) if tactics else 'social engineering'}.",
            "red_flags": red_flags,
            "social_engineering_tactics": tactics,
            "recommendation": "Do NOT click any links or download attachments. Report this email to your IT security team. Verify the sender through a separate communication channel.",
        }

        return jsonify({
            "success": True,
            "analysis": analysis,
            "powered_by": "Rule-Based Engine" if provider != "gemini" else "Rule-Based Fallback (set GEMINI_API_KEY for AI analysis)",
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/provider")
def api_provider():
    """Return the current AI provider configuration."""
    provider = config.AI_PROVIDER
    has_key = bool(config.GEMINI_API_KEY)

    if provider == "gemini" and has_key:
        status = "ai_active"
        label = f"Google Gemini ({config.GEMINI_MODEL})"
    elif provider == "gemini" and not has_key:
        status = "ai_no_key"
        label = "Gemini (No API Key — Using Fallback Templates)"
    else:
        status = "fallback"
        label = "Template Engine (No AI)"

    return jsonify({
        "success": True,
        "provider": provider,
        "status": status,
        "label": label,
        "has_key": has_key,
    })


# ─── Inbox Scanner API ──────────────────────────────────────────────────────────

@app.route("/api/inbox/connect", methods=["POST"])
def api_inbox_connect():
    """Connect to IMAP inbox and fetch recent emails."""
    try:
        data = request.get_json()
        email_addr = data.get("email", "")
        password = data.get("password", "")
        imap_server = data.get("imap_server", "")
        count = min(int(data.get("count", 15)), 30)

        if not email_addr or not password:
            return jsonify({"success": False, "error": "Email and password are required"}), 400

        connect_imap, fetch_inbox_emails, _ = _inbox_scanner()
        mail = connect_imap(email_addr, password, imap_server or None)
        emails = fetch_inbox_emails(mail, count=count)
        mail.logout()

        # Strip large HTML for the listing (keep it for individual analysis)
        listing = []
        for e in emails:
            listing.append({
                "uid": e["uid"],
                "subject": e["subject"],
                "sender_name": e["sender_name"],
                "sender_email": e["sender_email"],
                "date": e["date"],
                "has_attachments": len(e.get("attachments", [])) > 0,
                "link_count": len(e.get("links", [])),
                "snippet": (e.get("body_text", "") or "")[:150],
                "_full": e,  # Keep full data for analysis
            })

        # Store in session for subsequent analysis calls
        from flask import session
        session["inbox_emails"] = {e["uid"]: e for e in emails}

        return jsonify({
            "success": True,
            "count": len(listing),
            "emails": [{k: v for k, v in e.items() if k != "_full"} for e in listing],
        })

    except imaplib.IMAP4.error as e:
        error_msg = str(e)
        if "AUTHENTICATIONFAILED" in error_msg.upper() or "AUTH" in error_msg.upper():
            return jsonify({"success": False, "error": "Authentication failed. For Gmail, use an App Password (not your regular password). Enable 2FA → Google Account → Security → App Passwords."}), 401
        return jsonify({"success": False, "error": f"IMAP error: {error_msg}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/inbox/analyze", methods=["POST"])
def api_inbox_analyze():
    """Analyze a single inbox email with AI."""
    try:
        data = request.get_json()
        email_data = data.get("email_data")

        if not email_data:
            return jsonify({"success": False, "error": "No email data provided"}), 400

        _, _, analyze_email_with_ai = _inbox_scanner()
        analysis = analyze_email_with_ai(email_data)

        return jsonify({
            "success": True,
            "analysis": analysis,
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/inbox/scan", methods=["POST"])
def api_inbox_scan():
    """Connect to inbox, fetch emails, and analyze all with AI in one call."""
    try:
        data = request.get_json()
        email_addr = data.get("email", "")
        password = data.get("password", "")
        imap_server = data.get("imap_server", "")
        count = min(int(data.get("count", 10)), 20)

        if not email_addr or not password:
            return jsonify({"success": False, "error": "Email and password are required"}), 400

        connect_imap, fetch_inbox_emails, analyze_email_with_ai = _inbox_scanner()
        mail = connect_imap(email_addr, password, imap_server or None)
        if not mail:
            return jsonify({"success": False, "error": "Could not connect to email server. Check your credentials and IMAP settings."}), 500
        emails = fetch_inbox_emails(mail, count=count)
        mail.logout()

        results = []
        for e in emails:
            analysis = analyze_email_with_ai(e)
            results.append({
                "email": {
                    "uid": e.get("uid", e.get("id", "")),
                    "subject": e["subject"],
                    "sender_name": e["sender_name"],
                    "sender_email": e["sender_email"],
                    "date": e["date"],
                    "snippet": (e.get("body_text", "") or "")[:150],
                    "has_attachments": len(e.get("attachments", [])) > 0,
                },
                "analysis": analysis,
            })

        # Summary stats
        safe_count = sum(1 for r in results if r["analysis"].get("verdict") == "SAFE")
        suspicious_count = sum(1 for r in results if r["analysis"].get("verdict") == "SUSPICIOUS")
        phishing_count = sum(1 for r in results if r["analysis"].get("verdict") in ["PHISHING", "SPAM"])

        return jsonify({
            "success": True,
            "total": len(results),
            "summary": {
                "safe": safe_count,
                "suspicious": suspicious_count,
                "threats": phishing_count,
            },
            "results": results,
        })

    except imaplib.IMAP4.error as e:
        error_msg = str(e)
        if "AUTHENTICATIONFAILED" in error_msg.upper() or "AUTH" in error_msg.upper():
            return jsonify({"success": False, "error": "Authentication failed. For Gmail, use an App Password (not your regular password). Enable 2FA → Google Account → Security → App Passwords."}), 401
        return jsonify({"success": False, "error": f"IMAP error: {error_msg}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


import imaplib  # For exception handling


@app.route("/api/inbox/evaluate", methods=["POST"])
def api_inbox_evaluate():
    """
    Industry-standard accuracy evaluation. Body: { "samples": [ { "email_data": {...}, "true_verdict": "SAFE"|"PHISHING"|"SPAM"|"SUSPICIOUS"|"SCAM" }, ... ] }.
    Returns binary precision/recall/F1 and per-verdict metrics.
    """
    if not scanner_evaluate:
        return jsonify({"success": False, "error": "Scanner evaluation module not available"}), 501
    try:
        data = request.get_json() or {}
        samples = data.get("samples", [])
        if not samples:
            return jsonify({"success": False, "error": "samples array is required"}), 400
        _, _, analyze_email_with_ai = _inbox_scanner()
        metrics = scanner_evaluate(samples, analyze_email_with_ai)
        return jsonify({"success": True, "metrics": metrics})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scanner/config", methods=["GET", "POST"])
def api_scanner_config():
    """GET: return thresholds (dynamic from scanner_config.json). POST: update thresholds (no restart)."""
    try:
        import config as cfg
        if request.method == "POST":
            from scanner_config_loader import set_thresholds
            data = request.get_json() or {}
            p = int(data.get("threshold_phishing", 65))
            s = int(data.get("threshold_suspicious", 40))
            sp = int(data.get("threshold_spam", 22))
            ok = set_thresholds(p, s, sp)
            return jsonify({"success": ok})
        try:
            from scanner_config_loader import get_thresholds
            thr_p, thr_s, thr_sp = get_thresholds(cfg)
        except ImportError:
            thr_p = getattr(cfg, "SCANNER_THRESHOLD_PHISHING", 65)
            thr_s = getattr(cfg, "SCANNER_THRESHOLD_SUSPICIOUS", 40)
            thr_sp = getattr(cfg, "SCANNER_THRESHOLD_SPAM", 22)
        return jsonify({
            "success": True,
            "threshold_phishing": thr_p,
            "threshold_suspicious": thr_s,
            "threshold_spam": thr_sp,
            "analysis_cache_ttl_sec": getattr(cfg, "ANALYSIS_CACHE_TTL_SEC", 0),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scanner/rules", methods=["GET", "POST"])
def api_scanner_rules():
    """GET: return dynamic rule lists. POST: update extra keywords (cred_patterns, urgency, bec_patterns, ...)."""
    try:
        if request.method == "POST":
            from scanner_config_loader import update_rules
            ok = update_rules(request.get_json() or {})
            return jsonify({"success": ok})
        from scanner_config_loader import get_dynamic_rules
        return jsonify({"success": True, "rules": get_dynamic_rules()})
    except ImportError:
        return jsonify({"success": False, "error": "scanner_config_loader not available"}), 501
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel", methods=["GET"])
def api_threat_intel_get():
    """Get blocklist/allowlist and counts for UI."""
    if not threat_intel_get_lists:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        blocklist, allowlist = threat_intel_get_lists()
        bc, ac = get_blocklist_allowlist_counts() if get_blocklist_allowlist_counts else (len(blocklist), len(allowlist))
        return jsonify({
            "success": True,
            "blocklist": blocklist,
            "allowlist": allowlist,
            "blocklist_count": bc,
            "allowlist_count": ac,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/blocklist", methods=["POST"])
def api_threat_intel_blocklist_add():
    """Add domain to blocklist. Body: { "domain": "example.com" }."""
    if not threat_intel_add_blocklist:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        data = request.get_json() or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain or "@" in domain:
            return jsonify({"success": False, "error": "Valid domain (e.g. example.com) required"}), 400
        ok = threat_intel_add_blocklist(domain)
        return jsonify({"success": True, "added": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/blocklist/remove", methods=["POST"])
def api_threat_intel_blocklist_remove():
    """Remove domain from blocklist. Body: { "domain": "example.com" }."""
    if not threat_intel_remove_blocklist:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        data = request.get_json() or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"success": False, "error": "domain required"}), 400
        ok = threat_intel_remove_blocklist(domain)
        return jsonify({"success": True, "removed": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/allowlist", methods=["POST"])
def api_threat_intel_allowlist_add():
    """Add domain to allowlist. Body: { "domain": "example.com" }."""
    if not threat_intel_add_allowlist:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        data = request.get_json() or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain or "@" in domain:
            return jsonify({"success": False, "error": "Valid domain required"}), 400
        ok = threat_intel_add_allowlist(domain)
        return jsonify({"success": True, "added": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/allowlist/bulk", methods=["POST"])
def api_threat_intel_allowlist_bulk():
    """Add multiple domains to allowlist. Body: { "domains": ["bank.com.pk", "app.gov.pk"] }."""
    if not threat_intel_add_allowlist_bulk:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        data = request.get_json() or {}
        domains = data.get("domains") or []
        if not isinstance(domains, list):
            domains = [domains] if domains else []
        added = threat_intel_add_allowlist_bulk(domains)
        return jsonify({"success": True, "added": added, "domains": domains[:50]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/allowlist/remove", methods=["POST"])
def api_threat_intel_allowlist_remove():
    """Remove domain from allowlist. Body: { "domain": "example.com" }."""
    if not threat_intel_remove_allowlist:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        data = request.get_json() or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"success": False, "error": "domain required"}), 400
        ok = threat_intel_remove_allowlist(domain)
        return jsonify({"success": True, "removed": ok})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/threat-intel/reload", methods=["POST"])
def api_threat_intel_reload():
    """Reload blocklist/allowlist from disk (e.g. after editing threat_intel.json)."""
    if not threat_intel_reload:
        return jsonify({"success": False, "error": "Threat intel not available"}), 501
    try:
        threat_intel_reload()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/inbox/feedback", methods=["POST"])
def api_inbox_feedback():
    """
    Submit user correction for a scanned email (dynamic learning).
    Body: { "email_hash": "<from analysis.adaptive.email_hash>", "correct_verdict": "SAFE"|"PHISHING"|"SPAM"|"SUSPICIOUS"|"SCAM" }.
    Future scans from the same domain will be nudged by this feedback.
    """
    if not adaptive_submit_feedback:
        return jsonify({"success": False, "error": "Adaptive learning not available"}), 501
    try:
        data = request.get_json() or {}
        email_hash = data.get("email_hash", "").strip()
        correct_verdict = (data.get("correct_verdict") or "").strip().upper()
        if not email_hash:
            return jsonify({"success": False, "error": "email_hash is required"}), 400
        if correct_verdict not in ("SAFE", "PHISHING", "SPAM", "SUSPICIOUS", "SCAM"):
            return jsonify({"success": False, "error": "correct_verdict must be one of: SAFE, PHISHING, SPAM, SUSPICIOUS, SCAM"}), 400
        updated = adaptive_submit_feedback(email_hash, correct_verdict)
        return jsonify({"success": True, "updated": updated})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Send Email API ──────────────────────────────────────────────────────────────

@app.route("/api/send", methods=["POST"])
def api_send_email():
    """Send a generated phishing simulation email to a real inbox."""
    try:
        data = request.get_json()
        sender_email = data.get("sender_email", "")
        sender_password = data.get("sender_password", "")
        recipient_email = data.get("recipient_email", "")
        subject = data.get("subject", "")
        body_html = data.get("body_html", "")
        display_name = data.get("display_name", "")

        if not sender_email or not sender_password:
            return jsonify({"success": False, "error": "Sender email and app password are required"}), 400
        if not recipient_email:
            return jsonify({"success": False, "error": "Recipient email is required"}), 400
        if not subject or not body_html:
            return jsonify({"success": False, "error": "Generate an email first before sending"}), 400

        result = send_email(
            sender_email=sender_email,
            sender_password=sender_password,
            recipient_email=recipient_email,
            subject=subject,
            body_html=body_html,
            display_name=display_name,
        )

        if result["success"]:
            return jsonify({
                "success": True,
                "message": f"Email sent to {recipient_email}",
                "message_id": result["message_id"],
            })
        else:
            return jsonify({"success": False, "error": result["error"]}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Run ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "=" * 60)
    print("  AI Phishing Email Generator — Security Awareness Training")
    print(f"  Running at: http://127.0.0.1:{port}")
    print(f"  AI Provider: {config.AI_PROVIDER.upper()}")
    print("  100% FREE — No paid API keys required")
    print("=" * 60 + "\n")
    app.run(debug=config.DEBUG, host="0.0.0.0", port=port)
