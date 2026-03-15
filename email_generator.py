"""
Email Generation Module — parameterized phishing simulation templates.

Generates phishing-style emails for security awareness training using
industry-standard templates (no external API). Same pipeline for all environments.
"""


def _generate_email(params):
    """Generate a phishing simulation email from parameters (template-based)."""
    trigger = params.get("emotional_trigger", "urgency")
    context = params.get("context", "workplace")
    attachment_file = params.get("attachment_filename")
    suspicious_url = params.get("suspicious_url")
    display_text = params.get("display_text")

    scenarios = {
        "urgency": {
            "subject": "Action Required: Your account access expires in 2 hours",
            "sender": ("Security Team", "security-noreply@accounts-verify.com"),
            "body": "Our systems have detected that your account credentials are about to expire. To prevent loss of access to all company resources, you must verify your identity immediately.",
        },
        "authority": {
            "subject": "Directive from IT Security: Mandatory credential verification",
            "sender": ("Robert Chen, CISO", "r.chen@it-compliance.com"),
            "body": "As per corporate security policy CS-2025-017, all employees are required to complete a mandatory credential verification. This directive comes from the Office of the CISO and applies to all users without exception.",
        },
        "fear": {
            "subject": "ALERT: Unauthorized access detected on your account",
            "sender": ("Incident Response Team", "soc-alerts@security-ops.com"),
            "body": "Our Security Operations Center has detected multiple unauthorized login attempts from an unrecognized device. Your account has been flagged and will be permanently suspended within 24 hours unless you verify your identity.",
        },
        "reward": {
            "subject": "Congratulations! Your performance bonus of $2,500 has been approved",
            "sender": ("Payroll Department", "payroll-rewards@hr-portal.com"),
            "body": "Based on your outstanding Q4 performance, you have been selected to receive a special recognition bonus. To process the payment to your account, please verify your banking details through our secure portal.",
        },
        "curiosity": {
            "subject": "Confidential: Employee salary adjustments for 2025 (leaked)",
            "sender": ("Internal Memo", "internal-docs@corp-share.com"),
            "body": "An internal document containing the proposed salary adjustments for all departments has been shared with selected employees for review. This information is confidential and time-sensitive.",
        },
        "social_proof": {
            "subject": "Reminder: 94% of your team has completed the required security update",
            "sender": ("Compliance Dashboard", "compliance@team-status.com"),
            "body": "Our records show that most members of your department have already completed the mandatory security verification. You are among the few remaining employees who have not yet completed this requirement.",
        },
    }

    s = scenarios.get(trigger, scenarios["urgency"])

    link_html = ""
    if suspicious_url and display_text:
        link_html = f'<a href="{suspicious_url}" style="color: #0066cc; text-decoration: underline; font-weight: 600;">{display_text}</a>'

    attachment_html = ""
    if attachment_file:
        attachment_html = f'<div style="margin: 16px 0; padding: 12px 16px; background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 14px;"><strong>Attachment:</strong> <span style="color: #0066cc;">{attachment_file}</span></div>'

    body_html = f"""<div style="font-family: 'Segoe UI', -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; color: #1a1a2e;">
<div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; margin-bottom: 20px; border-radius: 0 6px 6px 0;">
<strong style="color: #92400e;">Important Notice</strong>
</div>
<p>Dear Employee,</p>
<p>{s['body']}</p>
{f'<p>Please {link_html} to proceed immediately.</p>' if link_html else '<p>Please contact your system administrator to proceed.</p>'}
{attachment_html}
<p style="color: #64748b; font-size: 13px;">This is an automated notification. Please do not reply directly to this email.</p>
<div style="margin-top: 28px; padding-top: 16px; border-top: 1px solid #e2e8f0;">
<strong>{s['sender'][0]}</strong><br>
<span style="color: #64748b; font-size: 13px;">{s['sender'][1]}</span>
</div>
</div>"""

    return {
        "subject": s["subject"],
        "body_html": body_html,
        "sender_name": s["sender"][0],
        "sender_email": s["sender"][1],
    }


# ─── Main Entry Point ──────────────────────────────────────────────────────────

def generate_email(params):
    """Generate a phishing simulation email from the given parameters (template-based)."""
    return _generate_email(params)
