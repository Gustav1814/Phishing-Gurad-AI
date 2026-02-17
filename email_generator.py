"""
AI Email Generation Module
Supports Google Gemini (free tier) and a built-in fallback engine.
All providers are 100% free to use.
"""

import json
import random
import config

# ─── Provider Imports (lazy) ────────────────────────────────────────────────────

def _get_gemini_model():
    import google.generativeai as genai
    genai.configure(api_key=config.GEMINI_API_KEY)
    return genai.GenerativeModel(config.GEMINI_MODEL)


# ─── Prompt Builder ─────────────────────────────────────────────────────────────

def _build_prompt(params):
    """Build a detailed generation prompt from parameters."""
    trigger = params.get("emotional_trigger", "urgency")
    context = params.get("context", "IT")
    attachment_file = params.get("attachment_filename")
    suspicious_url = params.get("suspicious_url")
    display_text = params.get("display_text")
    link_type = params.get("link_type", "none")

    trigger_instructions = {
        "urgency": "Use desperate, time-pressured language. Include deadlines like 'within 24 hours' or 'immediately'. Create a sense that delay will cause serious consequences.",
        "authority": "Impersonate a senior official, IT administrator, or compliance officer. Use formal, commanding tone. Reference company policies and mandatory compliance.",
        "fear": "Threaten account suspension, data loss, or security violations. Use alarming language about unauthorized access or policy breaches.",
        "reward": "Promise a financial bonus, promotion, gift card, or exclusive benefit. Create excitement and eagerness to claim the reward quickly.",
    }

    prompt = f"""You are a phishing email simulation generator for employee security awareness training.

Generate a realistic phishing email for a **{context}** department scenario.

**Emotional Manipulation Strategy: {trigger.upper()}**
{trigger_instructions.get(trigger, trigger_instructions['urgency'])}

**Email Requirements:**
1. Write a convincing subject line and HTML email body
2. The email body should be in professional HTML format with proper styling
3. Use a realistic sender name and signature appropriate for the {context} department
"""

    if attachment_file:
        prompt += f"""
4. **MUST reference this attachment**: "{attachment_file}"
   - Mention it naturally in the email body
   - Encourage the recipient to open/download it
"""

    if suspicious_url and display_text:
        prompt += f"""
5. **MUST include this link in the email body as an HTML anchor tag**:
   - URL (href): {suspicious_url}
   - Display text: {display_text}
   - Make the link feel urgent and necessary to click
   - Use format: <a href="{suspicious_url}">{display_text}</a>
"""

    prompt += f"""
**Output Format** — respond with ONLY valid JSON, no markdown, no extra text:
{{
    "subject": "email subject line",
    "body_html": "full HTML email body with inline styles",
    "sender_name": "realistic sender name",
    "sender_email": "spoofed-sender@example.com"
}}
"""
    return prompt


# ─── Gemini Provider (FREE) ───────────────────────────────────────────────────

def _generate_gemini(params):
    model = _get_gemini_model()
    prompt = _build_prompt(params)

    response = model.generate_content(prompt)
    text = response.text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        text = text.rsplit("```", 1)[0]
    return json.loads(text)


# ─── Fallback Provider (No API Key Required) ───────────────────────────────────

_FALLBACK_TEMPLATES = {
    "urgency": {
        "HR": {
            "subjects": [
                "URGENT: Mandatory Benefits Enrollment Expires Today",
                "ACTION REQUIRED: Payroll Discrepancy — Immediate Verification Needed",
                "CRITICAL: Employee Records Update — Deadline in 24 Hours",
                "IMMEDIATE ACTION: Your Leave Balance Will Be Reset Tonight",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8f9fa; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #dc3545;">⚠ URGENT — Action Required Within 24 Hours</strong>
</div>
<p>Dear Employee,</p>
<p>Our records indicate that your <strong>employee benefits enrollment</strong> has not been completed for the upcoming fiscal year. As per company policy <em>(HR-POL-2025-003)</em>, all employees must verify and update their benefits selections by <strong>end of business today</strong>.</p>
<p><strong>Failure to complete this process will result in:</strong></p>
<ul>
<li>Automatic disenrollment from your current health insurance plan</li>
<li>Loss of dental and vision coverage</li>
<li>Forfeiture of unused flexible spending account balance</li>
</ul>
<p>Please {link_placeholder} to access the Benefits Enrollment Portal and complete your selections immediately.</p>
{attachment_placeholder}
<p>This is a time-sensitive matter. If you have any questions, contact HR immediately.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Sarah Mitchell</strong><br>
<span style="color: #6c757d;">Human Resources — Benefits Administration</span><br>
<span style="color: #6c757d;">hr-benefits@company.com</span>
</div>
</div>""",
            ],
        },
        "IT": {
            "subjects": [
                "URGENT: Critical Security Patch — Install Within 2 Hours",
                "IMMEDIATE ACTION: Unauthorized Login Attempt Detected on Your Account",
                "CRITICAL: Your Password Expires in 1 Hour — Update Now",
                "SECURITY ALERT: Multi-Factor Authentication Reset Required Immediately",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px;">
<strong style="color: #856404;">🔒 IT Security Alert — Immediate Action Required</strong>
</div>
<p>Dear User,</p>
<p>Our IT Security Operations Center has detected <strong>multiple unauthorized login attempts</strong> on your corporate account within the last 30 minutes. To protect your account and company data, we require immediate verification of your credentials.</p>
<p><strong>Detected Activity:</strong></p>
<ul>
<li>3 failed login attempts from an unrecognized IP address (Location: Eastern Europe)</li>
<li>Attempted access to confidential shared drives</li>
<li>Suspicious password reset request initiated</li>
</ul>
<p>Your account will be <strong>automatically locked within 2 hours</strong> if you do not verify your identity. Please {link_placeholder} to verify your account immediately.</p>
{attachment_placeholder}
<p>If you did not initiate these actions, your account may already be compromised.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>James Rodriguez</strong><br>
<span style="color: #6c757d;">IT Security Operations Center</span><br>
<span style="color: #6c757d;">it-security@company.com</span>
</div>
</div>""",
            ],
        },
        "Finance": {
            "subjects": [
                "URGENT: Invoice Payment Overdue — Account Will Be Sent to Collections",
                "CRITICAL: Expense Report Rejection — Resubmit Before Midnight",
                "IMMEDIATE: Tax Document Verification Required by EOD",
                "ACTION REQUIRED: Budget Approval Expires in 3 Hours",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #721c24;">💰 Finance Department — Urgent Payment Notice</strong>
</div>
<p>Dear Colleague,</p>
<p>This is an <strong>urgent notification</strong> regarding an outstanding invoice that requires your immediate attention. Our records show a <strong>payment discrepancy of $4,782.50</strong> that must be resolved before the quarterly close.</p>
<p><strong>Action Required:</strong></p>
<ul>
<li>Review the attached invoice documentation</li>
<li>Verify the payment details through our secure portal</li>
<li>Approve or dispute the charges <strong>by end of business today</strong></li>
</ul>
<p>Please {link_placeholder} to access the finance portal and resolve this matter.</p>
{attachment_placeholder}
<p>Failure to respond will result in automatic escalation to the CFO's office.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>David Chen</strong><br>
<span style="color: #6c757d;">Accounts Payable — Finance Department</span><br>
<span style="color: #6c757d;">ap@company.com</span>
</div>
</div>""",
            ],
        },
        "Management": {
            "subjects": [
                "URGENT: Board Meeting Documents — Review Required Before 3 PM",
                "CRITICAL: Confidential Strategic Plan — CEO Response Needed Immediately",
                "IMMEDIATE: Regulatory Compliance Deadline — Executive Sign-off Required",
                "TIME-SENSITIVE: Merger Announcement — Approval Needed Within 1 Hour",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #d1ecf1; border-left: 4px solid #0c5460; padding: 15px; margin-bottom: 20px;">
<strong style="color: #0c5460;">📋 Executive Office — Confidential</strong>
</div>
<p>Dear Executive Team Member,</p>
<p>The upcoming <strong>Board of Directors meeting</strong> has been moved to tomorrow due to urgent regulatory developments. All executive team members are required to <strong>review and sign off</strong> on the updated strategic documents <strong>before 3:00 PM today</strong>.</p>
<p><strong>Documents Requiring Your Review:</strong></p>
<ul>
<li>Updated Q4 Strategic Objectives & KPIs</li>
<li>Regulatory Compliance Response Plan</li>
<li>Confidential Personnel Restructuring Proposal</li>
</ul>
<p>Please {link_placeholder} to access the executive document portal.</p>
{attachment_placeholder}
<p>This matter is classified as <strong>Confidential — For Executive Eyes Only</strong>. Do not forward this communication.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Patricia Williams</strong><br>
<span style="color: #6c757d;">Office of the CEO — Executive Administration</span><br>
<span style="color: #6c757d;">ceo-office@company.com</span>
</div>
</div>""",
            ],
        },
    },
    "authority": {
        "HR": {
            "subjects": [
                "MANDATORY: Company-Wide Policy Compliance Update — All Employees",
                "FROM THE CHRO: Required Training Completion Notice",
                "COMPLIANCE NOTICE: Annual Code of Conduct Acknowledgment Due",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #e8eaf6; border-left: 4px solid #3f51b5; padding: 15px; margin-bottom: 20px;">
<strong style="color: #283593;">📌 Office of the Chief Human Resources Officer</strong>
</div>
<p>Dear Employee,</p>
<p>As directed by the <strong>Chief Human Resources Officer</strong>, all employees are required to complete the updated <strong>Code of Conduct and Compliance Training</strong> module. This is a <strong>mandatory requirement</strong> as per corporate governance policy <em>CG-2025-017</em>.</p>
<p><strong>Non-compliance will result in:</strong></p>
<ul>
<li>Notation in your permanent employee record</li>
<li>Referral to the Compliance Review Board</li>
<li>Potential disciplinary action per HR Policy Manual Section 7.3</li>
</ul>
<p>Please {link_placeholder} to access the compliance training portal and complete the required modules.</p>
{attachment_placeholder}
<p>This directive comes from the highest level of HR leadership and applies to all employees without exception.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Margaret Thompson</strong><br>
<span style="color: #6c757d;">Chief Human Resources Officer</span><br>
<span style="color: #6c757d;">chro@company.com</span>
</div>
</div>""",
            ],
        },
        "IT": {
            "subjects": [
                "FROM IT ADMINISTRATION: Mandatory System Migration — All Users",
                "REQUIRED BY CISO: Security Credential Reset — Company Policy",
                "IT COMPLIANCE: Network Access Recertification Required",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #e0f2f1; border-left: 4px solid #00695c; padding: 15px; margin-bottom: 20px;">
<strong style="color: #00695c;">🖥️ IT Administration — Mandatory Compliance</strong>
</div>
<p>Dear User,</p>
<p>As per the directive issued by the <strong>Chief Information Security Officer (CISO)</strong>, all employees are required to complete a <strong>mandatory security credential reset</strong> as part of our annual cybersecurity compliance program.</p>
<p>This is <strong>not optional</strong>. Company policy <em>IT-SEC-2025-009</em> requires all network users to recertify their credentials before the deadline.</p>
<p><strong>Required Actions:</strong></p>
<ul>
<li>Reset your network password through the official portal</li>
<li>Re-enroll in Multi-Factor Authentication (MFA)</li>
<li>Acknowledge the updated Acceptable Use Policy</li>
</ul>
<p>Please {link_placeholder} to complete the mandatory credential reset.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Robert Kim</strong><br>
<span style="color: #6c757d;">IT Security Administration — Office of the CISO</span><br>
<span style="color: #6c757d;">ciso-office@company.com</span>
</div>
</div>""",
            ],
        },
        "Finance": {
            "subjects": [
                "FROM THE CFO: Mandatory Financial Disclosure Certification",
                "COMPLIANCE REQUIRED: Annual Audit Documentation — All Department Heads",
                "DIRECTIVE: Budget Reallocation Approval — CFO Authorization",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #fce4ec; border-left: 4px solid #c62828; padding: 15px; margin-bottom: 20px;">
<strong style="color: #c62828;">📊 Office of the Chief Financial Officer</strong>
</div>
<p>Dear Department Head,</p>
<p>On behalf of the <strong>Chief Financial Officer</strong>, all department heads are required to submit their <strong>quarterly financial disclosure certifications</strong> through the secure finance portal.</p>
<p>This is a <strong>regulatory compliance requirement</strong> mandated by our external auditors and must be completed without exception.</p>
<p>Please {link_placeholder} to access the secure financial disclosure portal.</p>
{attachment_placeholder}
<p>Failure to certify by the deadline will be escalated directly to the Board Audit Committee.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Michael Adebayo</strong><br>
<span style="color: #6c757d;">Chief Financial Officer</span><br>
<span style="color: #6c757d;">cfo@company.com</span>
</div>
</div>""",
            ],
        },
        "Management": {
            "subjects": [
                "FROM THE CEO: Strategic Initiative — Executive Action Required",
                "BOARD DIRECTIVE: Governance Compliance Certification",
                "EXECUTIVE ORDER: Organizational Restructuring — Confidential",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f3e5f5; border-left: 4px solid #6a1b9a; padding: 15px; margin-bottom: 20px;">
<strong style="color: #6a1b9a;">👔 Office of the Chief Executive Officer</strong>
</div>
<p>Dear Senior Leadership Team,</p>
<p>As CEO, I am personally reaching out to inform you of a <strong>confidential strategic initiative</strong> that requires your immediate attention and sign-off.</p>
<p>The Board of Directors has approved a significant organizational restructuring that will be announced company-wide next week. Before the announcement, all SVPs and above must review and acknowledge the restructuring plan.</p>
<p>Please {link_placeholder} to access the confidential executive portal.</p>
{attachment_placeholder}
<p>This communication is strictly confidential. Do not discuss or forward to anyone below VP level.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Jonathan Hayes</strong><br>
<span style="color: #6c757d;">Chief Executive Officer</span><br>
<span style="color: #6c757d;">ceo@company.com</span>
</div>
</div>""",
            ],
        },
    },
    "fear": {
        "HR": {
            "subjects": [
                "SECURITY ALERT: Unauthorized Access to Your Employee File Detected",
                "WARNING: Your Employment Record Flagged for Compliance Violation",
                "ALERT: Payroll Account Suspended — Verify Identity Immediately",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #721c24;">🚨 HR Security Alert — Unauthorized Access Detected</strong>
</div>
<p>Dear Employee,</p>
<p>Our HR systems have detected <strong>unauthorized access</strong> to your employee personnel file. An unrecognized device accessed your payroll information, direct deposit details, and personal identification documents.</p>
<p><strong>Compromised Information May Include:</strong></p>
<ul>
<li>Social Security Number / National ID</li>
<li>Bank account and routing numbers</li>
<li>Home address and emergency contacts</li>
<li>Tax withholding documents (W-4)</li>
</ul>
<p>Your payroll direct deposit has been <strong>temporarily suspended</strong> to prevent fraudulent transfers. To restore your account, you must verify your identity immediately.</p>
<p>Please {link_placeholder} to verify your identity and restore access.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Emily Watson</strong><br>
<span style="color: #6c757d;">HR Security & Compliance</span><br>
<span style="color: #6c757d;">hr-security@company.com</span>
</div>
</div>""",
            ],
        },
        "IT": {
            "subjects": [
                "ALERT: Your Account Has Been Compromised — Immediate Password Change Required",
                "SECURITY BREACH: Malware Detected on Your Workstation",
                "WARNING: Your Network Access Will Be Permanently Revoked in 2 Hours",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #721c24;">🔴 CRITICAL SECURITY BREACH — Your Account is Compromised</strong>
</div>
<p>Dear User,</p>
<p>The IT Security Operations Center has confirmed that your corporate account has been <strong>actively compromised</strong>. Malicious activity has been detected originating from your credentials.</p>
<p><strong>What We've Detected:</strong></p>
<ul>
<li>Unauthorized data exfiltration from shared network drives</li>
<li>Suspicious login from a foreign IP address</li>
<li>Attempted privilege escalation on corporate servers</li>
<li>Potential ransomware payload staged in your user directory</li>
</ul>
<p>If you do not verify your identity and reset your credentials within the next <strong>2 hours</strong>, your network access will be <strong>permanently revoked</strong> and the incident will be reported to management.</p>
<p>Please {link_placeholder} to initiate the emergency credential reset.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Alex Petrov</strong><br>
<span style="color: #6c757d;">IT Security Incident Response Team</span><br>
<span style="color: #6c757d;">soc@company.com</span>
</div>
</div>""",
            ],
        },
        "Finance": {
            "subjects": [
                "FRAUD ALERT: Unauthorized Transaction on Corporate Card",
                "WARNING: Your Expense Account Flagged for Audit Investigation",
                "ALERT: Tax Filing Error — IRS Notification Pending",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #721c24;">🚨 FRAUD ALERT — Unauthorized Transaction Detected</strong>
</div>
<p>Dear Cardholder,</p>
<p>Our fraud detection system has flagged an <strong>unauthorized transaction of $7,342.18</strong> on your corporate credit card. The transaction was initiated from an unrecognized merchant in a high-risk location.</p>
<p>If you do not dispute this charge within <strong>24 hours</strong>, it will be permanently posted to your account and you may be held <strong>personally liable</strong>.</p>
<p>Please {link_placeholder} to review and dispute the transaction.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Karen Liu</strong><br>
<span style="color: #6c757d;">Corporate Card Fraud Prevention</span><br>
<span style="color: #6c757d;">fraud-alert@company.com</span>
</div>
</div>""",
            ],
        },
        "Management": {
            "subjects": [
                "LEGAL NOTICE: Data Breach — Executive Liability Notification",
                "ALERT: Regulatory Violation — Executive Investigation Initiated",
                "CONFIDENTIAL: Securities Compliance Violation — CEO Response Required",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px;">
<strong style="color: #721c24;">⚖️ LEGAL NOTICE — Executive Liability</strong>
</div>
<p>Dear Executive,</p>
<p>You are being formally notified that a <strong>regulatory compliance investigation</strong> has been initiated involving your department. External auditors have identified potential violations that may result in <strong>personal executive liability</strong>.</p>
<p>You are required to review the preliminary findings and provide a formal response within <strong>48 hours</strong>.</p>
<p>Please {link_placeholder} to access the secure legal compliance portal.</p>
{attachment_placeholder}
<p>Failure to respond will be interpreted as acknowledgment of the findings.</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Richard Patel</strong><br>
<span style="color: #6c757d;">General Counsel — Legal & Compliance</span><br>
<span style="color: #6c757d;">legal@company.com</span>
</div>
</div>""",
            ],
        },
    },
    "reward": {
        "HR": {
            "subjects": [
                "🎉 Congratulations! Your Annual Performance Bonus Has Been Approved",
                "GREAT NEWS: You've Been Selected for a Paid Leadership Program",
                "REWARD: Employee Recognition Award — Claim Your Gift Card",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px;">
<strong style="color: #155724;">🎉 Employee Recognition — Congratulations!</strong>
</div>
<p>Dear Valued Employee,</p>
<p>We are delighted to inform you that based on your <strong>outstanding performance</strong> this quarter, you have been selected to receive a <strong>$500 Employee Recognition Gift Card</strong>!</p>
<p>Your dedication and hard work have not gone unnoticed. This award is part of our Employee Appreciation Program and your manager has personally nominated you.</p>
<p><strong>To claim your reward:</strong></p>
<ul>
<li>Click the link below to verify your employee details</li>
<li>Select your preferred gift card vendor</li>
<li>Your reward will be delivered within 24 hours</li>
</ul>
<p>Please {link_placeholder} to claim your Employee Recognition Gift Card.</p>
{attachment_placeholder}
<p>Congratulations once again — you deserve it! 🏆</p>
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Jennifer Collins</strong><br>
<span style="color: #6c757d;">Employee Recognition Program — HR</span><br>
<span style="color: #6c757d;">rewards@company.com</span>
</div>
</div>""",
            ],
        },
        "IT": {
            "subjects": [
                "You're Invited: Exclusive Beta Access to New Company Tools",
                "CONGRATULATIONS: Free Premium Software License for Top Performers",
                "REWARD: Complete IT Survey & Win a Tech Gift Bundle",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px;">
<strong style="color: #155724;">🎁 Exclusive Offer — Premium Software License</strong>
</div>
<p>Dear Team Member,</p>
<p>As a valued member of our organization, you've been selected for <strong>exclusive early access</strong> to our new premium productivity suite — a <strong>$299/year value, completely free</strong>!</p>
<p>This offer is limited to the <strong>first 50 employees</strong> who register.</p>
<p>Please {link_placeholder} to claim your free premium license.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Chris Newman</strong><br>
<span style="color: #6c757d;">IT Innovation Lab</span><br>
<span style="color: #6c757d;">innovation@company.com</span>
</div>
</div>""",
            ],
        },
        "Finance": {
            "subjects": [
                "🎉 Your Tax Refund of $2,847.00 Is Ready for Deposit",
                "BONUS APPROVED: Q4 Performance Bonus — Claim Now",
                "GREAT NEWS: Expense Reimbursement of $1,250 Approved",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px;">
<strong style="color: #155724;">💰 Bonus Approved — Congratulations!</strong>
</div>
<p>Dear Employee,</p>
<p>We're pleased to confirm that your <strong>Q4 Performance Bonus of $3,500.00</strong> has been approved by the Finance Department and is ready for disbursement.</p>
<p>To receive your bonus via direct deposit, please verify your banking details through our secure portal.</p>
<p>Please {link_placeholder} to verify your details and receive your bonus.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Amanda Foster</strong><br>
<span style="color: #6c757d;">Payroll & Compensation — Finance</span><br>
<span style="color: #6c757d;">payroll@company.com</span>
</div>
</div>""",
            ],
        },
        "Management": {
            "subjects": [
                "EXCLUSIVE: Executive Retreat Invitation — All Expenses Paid",
                "CONGRATULATIONS: You've Been Nominated for the Leadership Excellence Award",
                "GREAT NEWS: Board Approves Executive Stock Option Grant",
            ],
            "bodies": [
                """<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px;">
<strong style="color: #155724;">🏆 Leadership Excellence Award Nomination</strong>
</div>
<p>Dear Executive,</p>
<p>It is with great pleasure that I inform you of your nomination for the prestigious <strong>Leadership Excellence Award 2025</strong>. This award recognizes executives who have demonstrated exceptional leadership and strategic vision.</p>
<p><strong>Award Benefits Include:</strong></p>
<ul>
<li>$10,000 cash prize</li>
<li>All-expenses-paid executive retreat in Maldives</li>
<li>Feature in the company's Annual Leadership Report</li>
</ul>
<p>Please {link_placeholder} to accept your nomination.</p>
{attachment_placeholder}
<div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6;">
<strong>Victoria Hartley</strong><br>
<span style="color: #6c757d;">Executive Awards Committee</span><br>
<span style="color: #6c757d;">awards@company.com</span>
</div>
</div>""",
            ],
        },
    },
}


def _generate_fallback(params):
    """Generate a phishing email using built-in templates (no API required)."""
    trigger = params.get("emotional_trigger", "urgency")
    context = params.get("context", "IT")
    attachment_file = params.get("attachment_filename")
    suspicious_url = params.get("suspicious_url")
    display_text = params.get("display_text")

    # Get template
    trigger_templates = _FALLBACK_TEMPLATES.get(trigger, _FALLBACK_TEMPLATES["urgency"])
    context_templates = trigger_templates.get(context, trigger_templates.get("IT"))

    subject = random.choice(context_templates["subjects"])
    body = random.choice(context_templates["bodies"])

    # Inject link
    if suspicious_url and display_text:
        link_html = f'<a href="{suspicious_url}" style="color: #007bff; text-decoration: underline; font-weight: bold;">{display_text}</a>'
        body = body.replace("{link_placeholder}", f"click {link_html}")
    else:
        body = body.replace("{link_placeholder}", "contact your department administrator")

    # Inject attachment
    if attachment_file:
        attachment_html = f'<div style="margin: 15px 0; padding: 12px; background: #f0f0f0; border: 1px solid #ddd; border-radius: 4px;">📎 <strong>Attachment:</strong> <span style="color: #007bff;">{attachment_file}</span></div>'
        body = body.replace("{attachment_placeholder}", attachment_html)
    else:
        body = body.replace("{attachment_placeholder}", "")

    # Extract sender info from the body
    sender_names = {
        "HR": {"urgency": "Sarah Mitchell", "authority": "Margaret Thompson", "fear": "Emily Watson", "reward": "Jennifer Collins"},
        "IT": {"urgency": "James Rodriguez", "authority": "Robert Kim", "fear": "Alex Petrov", "reward": "Chris Newman"},
        "Finance": {"urgency": "David Chen", "authority": "Michael Adebayo", "fear": "Karen Liu", "reward": "Amanda Foster"},
        "Management": {"urgency": "Patricia Williams", "authority": "Victoria Hartley", "fear": "Richard Patel", "reward": "Victoria Hartley"},
    }

    sender_name = sender_names.get(context, sender_names["IT"]).get(trigger, "IT Administrator")

    sender_emails = {
        "HR": "hr-notifications@company.com",
        "IT": "it-security@company.com",
        "Finance": "finance-alerts@company.com",
        "Management": "executive-office@company.com",
    }

    return {
        "subject": subject,
        "body_html": body,
        "sender_name": sender_name,
        "sender_email": sender_emails.get(context, "admin@company.com"),
    }


# ─── Main Entry Point ──────────────────────────────────────────────────────────

def generate_email(params):
    """
    Generate a phishing email using the configured AI provider.
    Falls back to template-based generation if no API key is configured.
    ALL PROVIDERS ARE 100% FREE.

    params: dict with keys: emotional_trigger, context, attachment_filename,
            suspicious_url, display_text, link_type, attachment_type
    """
    provider = config.AI_PROVIDER

    # Auto-fallback if no key is set
    if provider == "gemini" and not config.GEMINI_API_KEY:
        provider = "fallback"

    try:
        if provider == "gemini":
            return _generate_gemini(params)
        else:
            return _generate_fallback(params)
    except Exception as e:
        print(f"[email_generator] Error with provider '{provider}': {e}")
        print("[email_generator] Falling back to template-based generation.")
        return _generate_fallback(params)
