"""
Indicator Injection Engine (Rule-Based)
Generates and validates phishing indicators: attachments, URLs, and emotional triggers.
"""

import random

# ─── Attachment Generation ─────────────────────────────────────────────────────

ATTACHMENT_TEMPLATES = {
    "double_extension": {
        "HR": [
            "Employee_Benefits_2025.pdf.exe",
            "Salary_Revision_Notice.docx.scr",
            "Annual_Leave_Policy.pdf.bat",
            "Performance_Review_Q4.xlsx.exe",
            "Onboarding_Checklist.pdf.com",
        ],
        "IT": [
            "Security_Patch_Update.pdf.exe",
            "VPN_Configuration_Guide.docx.scr",
            "System_Migration_Notice.pdf.bat",
            "Password_Reset_Tool.xlsx.exe",
            "Network_Audit_Report.pdf.com",
        ],
        "Finance": [
            "Q4_Budget_Report.pdf.exe",
            "Invoice_Payment_Details.xlsx.scr",
            "Tax_Filing_Summary.pdf.bat",
            "Expense_Reimbursement.docx.exe",
            "Audit_Findings_2025.pdf.com",
        ],
        "Management": [
            "Board_Meeting_Minutes.pdf.exe",
            "Strategic_Plan_2025.docx.scr",
            "Confidential_Memo.pdf.bat",
            "Quarterly_KPI_Dashboard.xlsx.exe",
            "Executive_Briefing.pdf.com",
        ],
    },
    "compressed": {
        "HR": [
            "Employee_Records_Update.zip",
            "Benefits_Enrollment_Forms.rar",
            "New_Hire_Documents.zip",
            "Payroll_Adjustment.7z",
        ],
        "IT": [
            "Critical_Security_Patch.zip",
            "Firewall_Logs_Export.rar",
            "Backup_Recovery_Tools.zip",
            "Server_Diagnostics.7z",
        ],
        "Finance": [
            "Tax_Documents_2025.zip",
            "Invoice_Attachments.rar",
            "Financial_Statements_Q4.zip",
            "Procurement_Orders.7z",
        ],
        "Management": [
            "Confidential_Strategy_Docs.zip",
            "Board_Resolutions.rar",
            "M_and_A_Documents.zip",
            "Executive_Reports.7z",
        ],
    },
    "macro_enabled": {
        "HR": [
            "Employee_Survey_Results.docm",
            "Training_Schedule_Interactive.xlsm",
            "Org_Chart_Update.docm",
            "Leave_Tracker_2025.xlsm",
        ],
        "IT": [
            "Infrastructure_Inventory.xlsm",
            "Incident_Report_Template.docm",
            "Asset_Management_Tool.xlsm",
            "Compliance_Checklist.docm",
        ],
        "Finance": [
            "Budget_Calculator_2025.xlsm",
            "Revenue_Forecast_Model.xlsm",
            "Expense_Report_Template.docm",
            "Financial_Dashboard.xlsm",
        ],
        "Management": [
            "Project_Timeline_Tracker.xlsm",
            "Risk_Assessment_Matrix.xlsm",
            "Performance_Scorecard.docm",
            "Resource_Allocation_Tool.xlsm",
        ],
    },
}


def generate_attachment(attachment_type, context):
    """
    Generate a realistic phishing attachment filename.
    Returns (filename, description) tuple.
    """
    if attachment_type == "none" or not attachment_type:
        return None, None

    templates = ATTACHMENT_TEMPLATES.get(attachment_type, {})
    options = templates.get(context, templates.get("IT", ["malicious_file.pdf.exe"]))
    filename = random.choice(options)

    descriptions = {
        "double_extension": f"Double extension file — the real extension is hidden. '{filename}' appears to be a document but is actually an executable.",
        "compressed": f"Compressed archive — '{filename}' could contain malicious executables. Users should never open unexpected compressed files.",
        "macro_enabled": f"Macro-enabled document — '{filename}' requires enabling macros, which can execute malicious code.",
    }
    description = descriptions.get(attachment_type, "Suspicious attachment detected.")
    return filename, description


# ─── URL Generation ────────────────────────────────────────────────────────────

DOMAIN_MAP = {
    "HR": {
        "legit": "hr-portal.company.com",
        "typosquat": ["hr-p0rtal.company.com", "hr-portai.company.com", "hr-porta1.c0mpany.com"],
        "subdomain_spoof": ["hr-portal.company.com.evil-site.net", "login.hr-portal.company.com.attacker.org"],
    },
    "IT": {
        "legit": "it-helpdesk.company.com",
        "typosquat": ["it-he1pdesk.company.com", "it-helpd3sk.company.com", "1t-helpdesk.c0mpany.com"],
        "subdomain_spoof": ["it-helpdesk.company.com.secure-login.net", "support.it-helpdesk.company.com.evil.org"],
    },
    "Finance": {
        "legit": "finance.company.com",
        "typosquat": ["f1nance.company.com", "finance.c0mpany.com", "flnance.company.com"],
        "subdomain_spoof": ["finance.company.com.secure-verify.net", "payment.finance.company.com.evil.org"],
    },
    "Management": {
        "legit": "executive.company.com",
        "typosquat": ["executlve.company.com", "executive.c0mpany.com", "execut1ve.company.com"],
        "subdomain_spoof": ["executive.company.com.board-meeting.net", "secure.executive.company.com.evil.org"],
    },
}

SHORTENED_URLS = [
    "https://bit.ly/3xKz9mQ",
    "https://t.ly/4RjW2",
    "https://tinyurl.com/y8mfz3p9",
    "https://is.gd/qR5tXv",
    "https://rb.gy/k2h7m",
    "https://cutt.ly/BwZ4nKp",
]

IP_URLS = [
    "http://192.168.1.45/login",
    "http://10.0.0.217/verify-account",
    "http://172.16.0.88/secure-portal",
    "http://203.0.113.42/auth/token",
    "http://198.51.100.73/password-reset",
]


def generate_url(link_type, context):
    """
    Generate a phishing URL of the specified type.
    Returns (url, display_text, description) tuple.
    """
    if link_type == "none" or not link_type:
        return None, None, None

    domain_info = DOMAIN_MAP.get(context, DOMAIN_MAP["IT"])

    if link_type == "ip_based":
        url = random.choice(IP_URLS)
        display_text = f"https://{domain_info['legit']}/secure-login"
        description = f"IP-based URL — '{url}' uses a raw IP address instead of a domain name. Legitimate services use proper domain names."

    elif link_type == "typosquatting":
        fake_domain = random.choice(domain_info["typosquat"])
        url = f"https://{fake_domain}/login"
        display_text = f"https://{domain_info['legit']}/login"
        description = f"Typosquatting — '{fake_domain}' looks similar to the real domain but contains character substitutions (e.g., '0' for 'o', '1' for 'l')."

    elif link_type == "shortened":
        url = random.choice(SHORTENED_URLS)
        display_text = "Click here to verify"
        description = f"URL shortener — '{url}' hides the true destination. The actual link could lead to any website."

    elif link_type == "subdomain_spoof":
        spoofed = random.choice(domain_info["subdomain_spoof"])
        url = f"https://{spoofed}/auth"
        display_text = f"Secure Login — {domain_info['legit']}"
        description = f"Subdomain spoofing — the URL appears to contain '{domain_info['legit']}' but the actual domain is controlled by an attacker."

    elif link_type == "http":
        url = f"http://{domain_info['legit']}/password-reset"
        display_text = f"Reset Your Password — {domain_info['legit']}"
        description = f"HTTP (no encryption) — '{url}' uses unencrypted HTTP instead of HTTPS. Legitimate login pages always use HTTPS."

    else:
        url = f"https://{domain_info['legit']}/login"
        display_text = "Login"
        description = "Standard link."

    return url, display_text, description


# ─── Emotional Trigger Metadata ────────────────────────────────────────────────

TRIGGER_METADATA = {
    "urgency": {
        "name": "Urgency",
        "description": "Creates pressure to act immediately, bypassing critical thinking. Look for phrases like 'immediately', 'within 24 hours', 'expires today'.",
        "keywords": ["immediately", "urgent", "expires", "deadline", "within 24 hours", "act now", "time-sensitive"],
    },
    "authority": {
        "name": "Authority",
        "description": "Impersonates a person or role of power to compel obedience. Watch for titles like 'CEO', 'IT Administrator', 'Director'.",
        "keywords": ["administrator", "director", "CEO", "management", "compliance", "mandatory", "required by policy"],
    },
    "fear": {
        "name": "Fear",
        "description": "Threatens negative consequences to provoke a panicked response. Key phrases: 'suspended', 'terminated', 'breach detected'.",
        "keywords": ["suspended", "terminated", "breach", "compromised", "unauthorized", "violation", "permanently deleted"],
    },
    "reward": {
        "name": "Reward",
        "description": "Promises something desirable to lure the victim into clicking. Look for: 'bonus', 'promotion', 'gift card', 'exclusive'.",
        "keywords": ["bonus", "promotion", "gift", "reward", "congratulations", "prize", "exclusive offer"],
    },
}


def get_trigger_metadata(trigger):
    """Return metadata for the selected emotional trigger."""
    return TRIGGER_METADATA.get(trigger, TRIGGER_METADATA["urgency"])


# ─── Indicator Validation ──────────────────────────────────────────────────────

def validate_indicators(email_html, params):
    """
    Validate that the generated email contains the expected indicators.
    Returns a list of validation results.
    """
    results = []

    # Check attachment reference
    if params.get("attachment_filename"):
        found = params["attachment_filename"].lower() in email_html.lower()
        results.append({
            "indicator": "Attachment Reference",
            "expected": params["attachment_filename"],
            "found": found,
        })

    # Check link reference
    if params.get("suspicious_url"):
        found = params["suspicious_url"] in email_html or params.get("display_text", "") in email_html
        results.append({
            "indicator": "Suspicious Link",
            "expected": params["suspicious_url"],
            "found": found,
        })

    return results


# ─── Build Full Indicator Report ───────────────────────────────────────────────

def build_indicator_report(params):
    """
    Build a comprehensive red-flag report for the generated email.
    Returns a list of indicator objects for the frontend highlight panel.
    """
    indicators = []

    # Emotional trigger
    trigger = params.get("emotional_trigger", "urgency")
    meta = get_trigger_metadata(trigger)
    indicators.append({
        "category": "Emotional Manipulation",
        "type": meta["name"],
        "description": meta["description"],
        "severity": "high",
        "keywords": meta["keywords"],
    })

    # Attachment
    if params.get("attachment_filename"):
        indicators.append({
            "category": "Suspicious Attachment",
            "type": params.get("attachment_type", "unknown").replace("_", " ").title(),
            "description": params.get("attachment_description", ""),
            "severity": "critical",
            "filename": params["attachment_filename"],
        })

    # Link
    if params.get("suspicious_url"):
        indicators.append({
            "category": "Suspicious Link",
            "type": params.get("link_type", "unknown").replace("_", " ").title(),
            "description": params.get("url_description", ""),
            "severity": "critical",
            "url": params["suspicious_url"],
            "display_text": params.get("display_text", ""),
        })

    return indicators
