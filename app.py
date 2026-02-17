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

app = Flask(__name__)
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


init_db()


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


# ─── Run ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AI Phishing Email Generator — Security Awareness Training")
    print("  Running at: http://127.0.0.1:5000")
    print(f"  AI Provider: {config.AI_PROVIDER.upper()}")
    print("  100% FREE — No paid API keys required")
    print("=" * 60 + "\n")
    app.run(debug=config.DEBUG, port=5000)
