"""
AI Email Generation Module — Gemini AI-First
Uses Google Gemini to generate unique, dynamic phishing simulation emails.
Falls back to a lightweight template only if Gemini is unavailable.
"""

import json
import random
import traceback
import config


def _get_gemini_model():
    import google.generativeai as genai
    genai.configure(api_key=config.GEMINI_API_KEY)
    return genai.GenerativeModel(config.GEMINI_MODEL)


# ─── AI Prompt Builder ──────────────────────────────────────────────────────────

def _build_prompt(params):
    """Build a detailed generation prompt from parameters."""
    trigger = params.get("emotional_trigger", "urgency")
    context = params.get("context", "workplace")
    attachment_file = params.get("attachment_filename")
    suspicious_url = params.get("suspicious_url")
    display_text = params.get("display_text")

    trigger_instructions = {
        "urgency": "Use desperate, time-pressured language. Include tight deadlines like 'within 2 hours' or 'by end of day'. Make it feel like delay will cause serious consequences such as account lock, data loss, or missed payments.",
        "authority": "Impersonate a senior executive, IT director, CISO, or compliance officer. Use formal commanding tone. Reference specific company policies, regulatory mandates, and chain-of-command.",
        "fear": "Threaten account suspension, security breach consequences, data exposure, or job-related penalties. Use alarming language about unauthorized access, compliance violations, or legal action.",
        "reward": "Promise a financial bonus, promotion, exclusive access, gift card, or special recognition. Create excitement and FOMO. Make the reward feel exclusive and time-limited.",
        "curiosity": "Tease intriguing information the recipient 'needs to see'. Reference leaked documents, salary lists, reorganization plans, or shocking internal news. Make them desperate to click.",
        "social_proof": "Reference that 'most employees have already completed this' or 'your team members have already verified'. Create pressure through peer compliance and fear of being the outlier.",
    }

    context_descriptions = {
        "workplace": "corporate IT/HR department at a Fortune 500 company",
        "banking": "financial institution, bank, or payment processor (e.g., Chase, PayPal, Wells Fargo style)",
        "ecommerce": "e-commerce platform or retail brand (e.g., Amazon, eBay, Shopify style)",
        "government": "government agency or legal/regulatory body (e.g., IRS, SEC, DOJ style)",
        "healthcare": "healthcare provider, hospital system, or insurance company (e.g., UnitedHealth, Medicare style)",
        "education": "university, academic institution, or educational platform (e.g., university IT, student services style)",
    }

    context_desc = context_descriptions.get(context, context_descriptions["workplace"])

    prompt = f"""You are an expert phishing email simulation generator for enterprise security awareness training.

Generate a HIGHLY REALISTIC, UNIQUE phishing email for a **{context_desc}** scenario.

EMOTIONAL MANIPULATION STRATEGY: **{trigger.upper()}**
{trigger_instructions.get(trigger, trigger_instructions['urgency'])}

REQUIREMENTS:
1. Write a convincing, realistic subject line (no ALL CAPS unless it's a genuine alert style)
2. Write the email body in clean, professional HTML with inline CSS styling
3. Use a realistic sender name and email that fits the {context} context
4. The email should look indistinguishable from a real corporate email
5. Include a professional signature block with name, title, department, and contact
6. Vary the writing style, tone, and scenario each time (don't repeat patterns)
7. Make it sophisticated enough that a trained employee might hesitate before recognizing it
"""

    if attachment_file:
        prompt += f"""
8. MUST naturally reference this attachment in the body: "{attachment_file}"
   - Mention it as critical documentation they need to review/download
"""

    if suspicious_url and display_text:
        prompt += f"""
9. MUST include this exact HTML link in the email body:
   <a href="{suspicious_url}">{display_text}</a>
   - Make the link feel urgent and necessary to click
"""

    prompt += """
RESPOND WITH ONLY VALID JSON (no markdown, no extra text, no code fences):
{
    "subject": "realistic email subject line",
    "body_html": "full HTML email body with inline styles, professional formatting, and signature",
    "sender_name": "realistic full name",
    "sender_email": "realistic-looking@domain.com"
}"""
    return prompt


# ─── Gemini AI Generation ───────────────────────────────────────────────────────

def _generate_gemini(params):
    """Generate a unique phishing email using Google Gemini AI."""
    model = _get_gemini_model()
    prompt = _build_prompt(params)

    response = model.generate_content(prompt)
    text = response.text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        text = text.rsplit("```", 1)[0].strip()

    result = json.loads(text)

    # Validate required fields
    for key in ("subject", "body_html", "sender_name", "sender_email"):
        if key not in result:
            raise ValueError(f"Missing required field: {key}")

    return result


# ─── Lightweight Fallback (No API) ──────────────────────────────────────────────

def _generate_fallback(params):
    """Simple fallback when Gemini API is unavailable."""
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
    """
    Generate a phishing email using Gemini AI first, fallback if unavailable.
    """
    provider = config.AI_PROVIDER

    if provider == "gemini" and not config.GEMINI_API_KEY:
        provider = "fallback"

    try:
        if provider == "gemini":
            return _generate_gemini(params)
        else:
            return _generate_fallback(params)
    except Exception as e:
        print(f"[email_generator] AI generation error: {e}")
        traceback.print_exc()
        print("[email_generator] Falling back to template generation.")
        return _generate_fallback(params)
