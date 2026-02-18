"""
inbox_scanner.py — Full-Spectrum Adaptive AI Email Threat Analyzer
Connects to IMAP and uses Google Gemini AI for real-time classification of
phishing, scams, spam, BEC, malware delivery, impersonation, and social engineering.
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import html
import re
import json
import traceback

import google.generativeai as genai
import config


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


def extract_email_content(msg):
    """Extract subject, sender, date, and body from an email.Message object."""
    subject = decode_mime_header(msg.get("Subject", "No Subject"))
    sender = decode_mime_header(msg.get("From", "Unknown Sender"))
    date = decode_mime_header(msg.get("Date", "Unknown Date"))
    
    sender_name, sender_email = parseaddr(sender)

    body_text = ""
    body_html = ""
    attachments = []
    links = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = decode_mime_header(part.get_filename())
                if filename:
                    attachments.append(filename)
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

    # Extract links from HTML body
    if body_html:
        found_links = re.findall(r'href=[\'"]?([^\'" >]+)', body_html)
        links.extend(found_links)
    
    # Also look for links in text body
    if body_text:
        text_links = re.findall(r'(https?://[^\s]+)', body_text)
        links.extend(text_links)

    return {
        "subject": subject,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "date": date,
        "body_text": body_text[:5000],
        "body_html": body_html[:5000],
        "attachments": attachments,
        "links": list(set(links))
    }


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

def analyze_email_with_ai(email_data):
    """
    Adaptive AI threat analysis using Google Gemini.
    Detects ALL email threats: phishing, spear-phishing, BEC, 419 scams,
    tech support scams, malware, spam, invoice fraud, impersonation, and social engineering.
    """
    if not config.GEMINI_API_KEY:
        return _fallback_analysis(email_data)

    try:
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel(config.GEMINI_MODEL)

        links_str = "\n".join(email_data.get("links", [])[:10]) if email_data.get("links") else "No links"
        attachments_str = ", ".join(email_data.get("attachments", [])) if email_data.get("attachments") else "No attachments"
        body = email_data.get("body_text", "") or _strip_html(email_data.get("body_html", ""))

        prompt = f"""You are an elite cybersecurity SOC analyst performing real-time threat triage on live email traffic.
Classify this email across the FULL spectrum of email-borne threats with surgical precision.

=== THREAT CATEGORIES ===
1. PHISHING: Credential harvesting, fake login pages, account verification scams
2. SPEAR PHISHING: Targeted attacks using specific names, roles, or internal info
3. BEC (Business Email Compromise): CEO fraud, invoice redirect, wire transfer requests
4. 419 / ADVANCE FEE SCAM: Inheritance, lottery winnings, investment schemes, Nigerian prince
5. TECH SUPPORT SCAM: Fake virus alerts, "device infected", call-this-number
6. MALWARE: Dangerous attachments (.exe .bat .scr macro-enabled docs, HTML files)
7. SPAM: Unsolicited marketing, crypto pumps, adult content, fake products
8. INVOICE / PAYMENT FRAUD: Fake invoices, overdue notices, fake receipts
9. IMPERSONATION: Display name spoofing, look-alike domains, brand impersonation
10. SOCIAL ENGINEERING: Curiosity traps, fake leaked docs, fake emergencies

=== ANALYSIS RULES ===
- NEVER trust domain alone. gmail.com/outlook.com/yahoo.com are used by attackers constantly.
- Flag MISMATCHES: Display name "PayPal Support" but email is random@gmail.com = PHISHING.
- Analyze INTENT: What does the email WANT? Click? Download? Send money? Reply with info?
- Inspect ALL LINKS: IP-based URLs, shorteners, mismatched anchor vs href, non-HTTPS.
- Check MANIPULATION: Urgency, fear, authority, reward, curiosity, social proof, scarcity.
- SIMULATION MARKERS: "[PhishGuard AI Simulation]" or "simulated phishing" = mark as PHISHING.
- Legitimate newsletters from VERIFIED services (matching domain, no credential requests) = SAFE.

=== EMAIL DATA ===
Subject: {email_data.get('subject', 'N/A')}
From (Display Name): {email_data.get('sender_name', 'N/A')}
From (Email): {email_data.get('sender_email', 'N/A')}
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
        return analysis

    except Exception as e:
        print(f"[inbox_scanner] Gemini analysis error: {e}")
        traceback.print_exc()
        return _fallback_analysis(email_data)


def _strip_html(html_str):
    """Remove HTML tags from a string."""
    return re.sub('<[^<]+?>', '', html_str)


# ─── Robust Fallback Analysis ───────────────────────────────────────────────────

def _fallback_analysis(email_data):
    """
    Multi-category rule-based analysis covering phishing, spam, scams,
    BEC, impersonation, malware, and social engineering indicators.
    """
    body = (email_data.get("body_text", "") or _strip_html(email_data.get("body_html", ""))).lower()
    sender_email = email_data.get("sender_email", "").lower()
    sender_name = email_data.get("sender_name", "").lower()
    subject = email_data.get("subject", "").lower()
    links = email_data.get("links", [])

    threat_score = 0
    red_flags = []
    positive_signals = []
    detected_category = "legitimate"

    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    free_providers = ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "aol.com", "icloud.com", "ymail.com", "protonmail.com"]

    # 1. PhishGuard Simulation Detection
    if "phishguard" in body or "simulated phishing" in body or "phishguard ai" in body:
        red_flags.append({"flag": "Simulated Phishing Test", "severity": "critical", "explanation": "Contains PhishGuard AI simulation markers"})
        threat_score += 60
        detected_category = "phishing"

    # 2. Display Name Spoofing
    brand_keywords = ["apple", "google", "microsoft", "paypal", "amazon", "netflix", "bank", "support", "security", "admin", "payroll", "chase", "citibank", "wells fargo", "irs", "tax"]
    for brand in brand_keywords:
        if brand in sender_name and sender_domain in free_providers:
            red_flags.append({"flag": "Display Name Spoofing", "severity": "critical", "explanation": f"Claims '{brand}' but uses free provider '{sender_domain}'"})
            threat_score += 40
            detected_category = "impersonation"
            break

    # 3. Credential Harvesting
    cred_patterns = ["verify your account", "confirm your identity", "update your password", "enter your credentials", "click here to verify", "reset your password", "confirm your email", "validate your login", "sign in to confirm"]
    found_cred = [p for p in cred_patterns if p in body]
    if found_cred:
        red_flags.append({"flag": "Credential Harvesting", "severity": "high", "explanation": f"Requests: '{found_cred[0]}'"})
        threat_score += 25
        if detected_category == "legitimate":
            detected_category = "phishing"

    # 4. Urgency & Emotional Manipulation
    urgency = ["urgent", "immediately", "act now", "suspended", "unauthorized", "expires", "terminated", "within 24 hours", "within 2 hours", "failure to comply", "last warning", "final notice"]
    found_urgency = [w for w in urgency if w in subject or w in body]
    if found_urgency:
        red_flags.append({"flag": "Urgency / Pressure Tactics", "severity": "high", "explanation": f"Pressure words: {', '.join(found_urgency[:3])}"})
        threat_score += 20

    # 5. Financial Scam Indicators (419, advance fee, crypto)
    scam_patterns = ["million dollars", "inheritance", "unclaimed funds", "lottery winner", "congratulations you have won", "wire transfer", "western union", "bitcoin opportunity", "crypto investment", "double your money", "guaranteed return", "beneficiary", "next of kin"]
    found_scam = [p for p in scam_patterns if p in body]
    if found_scam:
        red_flags.append({"flag": "Financial Scam", "severity": "critical", "explanation": f"Classic scam language: '{found_scam[0]}'"})
        threat_score += 40
        detected_category = "scam"

    # 6. Spam Indicators
    spam_patterns = ["unsubscribe", "click here to opt out", "weight loss", "enlargement", "limited time offer", "special promotion", "buy now", "discount code", "free trial", "no obligation"]
    found_spam = [p for p in spam_patterns if p in body]
    if found_spam and len(found_spam) >= 2:
        red_flags.append({"flag": "Spam Content", "severity": "medium", "explanation": f"Spam indicators: {', '.join(found_spam[:3])}"})
        threat_score += 15
        if detected_category == "legitimate":
            detected_category = "spam"

    # 7. Suspicious Links
    suspicious_links = []
    for link in links:
        l = link.lower()
        if any(x in l for x in ["bit.ly", "tinyurl", "goo.gl", "is.gd", "t.co", "rb.gy", "cutt.ly"]):
            suspicious_links.append("URL shortener")
        elif re.match(r'https?://\d+\.\d+\.\d+\.\d+', l):
            suspicious_links.append("IP-based URL")
        elif any(x in l for x in ["ngrok", "loclx", "serveo", "localtunnel"]):
            suspicious_links.append("Tunnel/proxy")
        elif "http://" in l and "https://" not in l:
            suspicious_links.append("Unencrypted HTTP")

    if suspicious_links:
        red_flags.append({"flag": "Suspicious Links", "severity": "high", "explanation": f"Found: {', '.join(set(suspicious_links))}"})
        threat_score += 25

    # 8. Dangerous Attachments
    danger_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".docm", ".xlsm", ".html", ".htm", ".iso", ".img"]
    bad_attachments = [a for a in email_data.get("attachments", []) if any(a.lower().endswith(e) for e in danger_exts)]
    if bad_attachments:
        red_flags.append({"flag": "Dangerous Attachment", "severity": "critical", "explanation": f"Malicious file: {', '.join(bad_attachments)}"})
        threat_score += 35
        if detected_category == "legitimate":
            detected_category = "malware"

    # Positive signals only if zero red flags
    trusted = ["google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "linkedin.com"]
    if sender_domain in trusted and threat_score == 0:
        positive_signals.append(f"Verified enterprise sender ({sender_domain})")
    if not red_flags:
        positive_signals.append("No suspicious indicators detected")

    threat_score = max(0, min(100, threat_score))

    if threat_score >= 60:
        verdict = "PHISHING"
    elif threat_score >= 35:
        verdict = "SUSPICIOUS"
    elif threat_score >= 15:
        verdict = "SPAM"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "confidence": 75,
        "threat_score": threat_score,
        "summary": f"Detected {len(red_flags)} threat indicator(s). " + (red_flags[0]['explanation'] if red_flags else "No significant threats found."),
        "red_flags": red_flags,
        "positive_signals": positive_signals if positive_signals else ["No specific safe signals"],
        "category": detected_category,
        "recommendation": "Delete and report immediately" if threat_score >= 60 else ("Proceed with extreme caution" if threat_score >= 35 else "This email appears safe"),
        "ai_powered": False,
    }
