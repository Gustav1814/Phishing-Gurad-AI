"""
scanner_features.py — Industry-standard feature extraction for the trainable email threat model.

Single pipeline for training and inference: same features, same order, no API calls.
Used by train_scanner_model.py and inbox_scanner when AI_PROVIDER=local.
Advanced + dynamic: punycode, reply mismatch, BEC/urgency, extended word counts.
"""

import re
from typing import Any, Dict, List, Optional

# Bump when feature set changes so saved models can validate
FEATURE_VERSION = 2

# Trusted domains (same concept as inbox_scanner / adaptive_learning)
TRUSTED_DOMAINS = frozenset({
    "linkedin.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "openai.com", "netflix.com", "paypal.com", "stripe.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com", "slack.com",
    "zoom.us", "dropbox.com", "adobe.com", "salesforce.com", "notion.so",
    "gamma.app", "canva.com", "figma.com", "vercel.com", "netlify.com",
    "hubspot.com", "mailchimp.com", "sendgrid.net",
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
    # Pakistan: banks, telcos, gov
    "hbl.com", "ubl.com.pk", "mcb.com.pk", "meezanbank.com", "faysalbank.com",
    "jsbank.com", "bankalfalah.com", "askaribank.com", "habibmetropolitan.com", "soneribank.com",
    "sbp.org.pk", "nadra.gov.pk", "jazz.com.pk", "jazzcash.com.pk", "easypaisa.com.pk",
    "telenor.com.pk", "ptcl.com.pk", "zong.com.pk", "wapda.gov.pk", "fbr.gov.pk", "pakistan.gov.pk",
})

FREE_EMAIL_DOMAINS = frozenset({"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "ymail.com"})

# Keywords that often appear in phishing/scam (binary counts in body/subject)
THREAT_KEYWORDS = [
    "verify your account", "confirm your identity", "update your password", "click here to verify",
    "wire transfer", "suspended", "unauthorized", "act now", "within 24 hours", "final notice",
    "inheritance", "million dollars", "lottery", "bitcoin", "crypto", "beneficiary",
    "your device is infected", "call this number", "tech support", "virus detected",
]

# Safe / legitimate indicators
SAFE_KEYWORDS = ["unsubscribe", "view in browser", "you requested", "order confirmation", "shipping update"]

# Extended unigrams for threat (single words) — normalized count
THREAT_UNIGRAMS = [
    "verify", "account", "password", "click", "suspend", "urgent", "wire", "transfer", "confirm",
    "identity", "immediately", "warning", "breach", "compromise", "locked", "verify", "secure",
    "phishing", "victim", "beneficiary", "lottery", "inheritance", "bitcoin", "crypto", "fee",
    "ceo", "executive", "vendor", "invoice", "payment", "bank",
]

# Safe unigrams
SAFE_UNIGRAMS = [
    "unsubscribe", "order", "confirmation", "shipping", "tracking", "receipt", "newsletter",
    "notification", "requested", "settings", "preferences", "team", "support",
]


def _sender_domain(email_data: Dict[str, Any]) -> str:
    return (email_data.get("sender_email") or "").split("@")[-1].lower()


def _body_text(email_data: Dict[str, Any]) -> str:
    body = (email_data.get("body_text") or "").strip()
    if not body and email_data.get("body_html"):
        body = re.sub("<[^>]+>", "", (email_data.get("body_html") or ""))
    return body[:5000]


def extract_features(email_data: Dict[str, Any]) -> Optional[List[float]]:
    """
    Extract a fixed-size feature vector for the classifier.
    Returns 30+ features in a fixed order; None if input invalid.
    Used for both training and inference — same order every time.
    """
    try:
        domain = _sender_domain(email_data)
        subject = (email_data.get("subject") or "")[:500]
        body = _body_text(email_data)
        links = email_data.get("links") or []
        attachments = email_data.get("attachments") or []
        auth = email_data.get("auth_results") or {}
        list_unsub = (email_data.get("list_unsubscribe") or "").strip()
        link_display_pairs = email_data.get("link_display_pairs") or []

        # 1. Domain / sender (3)
        domain_hash = (hash(domain) % 1000) / 1000.0
        is_trusted = 1.0 if any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS) else 0.0
        domain_len_norm = min(len(domain), 50) / 50.0

        # 2. Links (5)
        n_links = min(len(links), 25) / 25.0
        has_shortener = 1.0 if any(s in " ".join(links).lower() for s in ("bit.ly", "tinyurl", "goo.gl", "t.co", "rb.gy")) else 0.0
        has_ip_url = 1.0 if any(re.match(r"https?://\d+\.\d+\.\d+\.\d+", l) for l in links) else 0.0
        has_tunnel = 1.0 if any(x in " ".join(links).lower() for x in ("ngrok", "loclx", "serveo")) else 0.0
        n_link_display_pairs = min(len(link_display_pairs), 10) / 10.0

        # 3. Auth (3)
        spf_pass = 1.0 if auth.get("spf") == "pass" else 0.0
        dkim_pass = 1.0 if auth.get("dkim") == "pass" else 0.0
        dmarc_pass = 1.0 if auth.get("dmarc") == "pass" else 0.0

        # 4. Content length (3)
        subject_len = min(len(subject), 300) / 300.0
        body_len = min(len(body), 5000) / 5000.0
        n_attachments = min(len(attachments), 10) / 10.0

        # 5. Keyword counts in subject + body (normalized) (4)
        combined = (subject + " " + body).lower()
        threat_keyword_count = sum(1 for k in THREAT_KEYWORDS if k in combined)
        threat_keyword_norm = min(threat_keyword_count, 10) / 10.0
        safe_keyword_count = sum(1 for k in SAFE_KEYWORDS if k in combined)
        safe_keyword_norm = min(safe_keyword_count, 5) / 5.0
        urgency_count = sum(1 for u in ["urgent", "asap", "immediately", "last warning", "act now"] if u in combined)
        urgency_norm = min(urgency_count, 5) / 5.0
        login_like = 1.0 if any(p in combined for p in ["login", "sign in", "password", "verify your account"]) else 0.0

        # 6. Legitimacy signals (2)
        has_list_unsubscribe = 1.0 if list_unsub else 0.0
        reply_to_present = 1.0 if (email_data.get("reply_to_email") or "").strip() else 0.0

        # 7. Dangerous attachment hint (1)
        danger_exts = (".exe", ".scr", ".bat", ".docm", ".xlsm", ".jar", ".vbs")
        has_danger_attachment = 1.0 if any(
            (a or "").lower().endswith(e) for a in attachments for e in danger_exts
        ) else 0.0

        # 8. Reply-To vs From domain mismatch (1)
        reply_to = (email_data.get("reply_to_email") or "").strip().lower()
        if reply_to and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1]
            reply_mismatch = 1.0 if reply_domain != domain else 0.0
        else:
            reply_mismatch = 0.0

        # 9. Advanced: punycode in links (homograph phishing) (1)
        links_str = " ".join(links).lower()
        has_punycode = 1.0 if "xn--" in links_str else 0.0

        # 10. BEC/urgency phrase count (normalized) (1)
        bec_phrases = ["wire transfer", "bank account", "ceo", "vendor", "urgent", "confidential", "as per", "payment to"]
        bec_count = sum(1 for p in bec_phrases if p in combined)
        bec_norm = min(bec_count, 5) / 5.0

        # 11. Exclamation / caps ratio in subject (1)
        sub = subject.strip()
        if sub:
            exclam = sub.count("!") / max(len(sub), 1)
            caps_ratio = sum(1 for c in sub if c.isupper()) / max(len(sub), 1)
            urgency_subject = min(exclam * 10 + caps_ratio * 5, 1.0)
        else:
            urgency_subject = 0.0

        # 12. Digit ratio in subject (phishing often uses numbers) (1)
        if sub:
            digit_ratio = sum(1 for c in sub if c.isdigit()) / max(len(sub), 1)
        else:
            digit_ratio = 0.0

        # 13. Free email + display name (impersonation hint) (1)
        sender_name = (email_data.get("sender_name") or "").lower()
        brand_like = any(b in sender_name for b in ["paypal", "amazon", "microsoft", "apple", "bank", "support", "security", "admin"])
        is_free_sender = domain in FREE_EMAIL_DOMAINS
        impersonation_hint = 1.0 if (is_free_sender and brand_like) else 0.0

        # 14. Login-like path in links (1)
        login_path_count = 0
        for link in links:
            if any(p in link.lower() for p in ["/login", "/signin", "/verify", "/account", "/secure"]):
                login_path_count += 1
        login_path_norm = min(login_path_count, 5) / 5.0

        # 15. Extended threat unigram count (1)
        words = set(re.findall(r"[a-z0-9]+", combined))
        threat_uni_count = sum(1 for w in THREAT_UNIGRAMS if w in words)
        threat_uni_norm = min(threat_uni_count, 15) / 15.0

        # 16. Safe unigram count (1)
        safe_uni_count = sum(1 for w in SAFE_UNIGRAMS if w in words)
        safe_uni_norm = min(safe_uni_count, 10) / 10.0

        features = [
            domain_hash,
            is_trusted,
            domain_len_norm,
            n_links,
            has_shortener,
            has_ip_url,
            has_tunnel,
            n_link_display_pairs,
            spf_pass,
            dkim_pass,
            dmarc_pass,
            subject_len,
            body_len,
            n_attachments,
            threat_keyword_norm,
            safe_keyword_norm,
            urgency_norm,
            login_like,
            has_list_unsubscribe,
            reply_to_present,
            has_danger_attachment,
            reply_mismatch,
            has_punycode,
            bec_norm,
            urgency_subject,
            digit_ratio,
            impersonation_hint,
            login_path_norm,
            threat_uni_norm,
            safe_uni_norm,
        ]
        return [float(x) for x in features]
    except Exception:
        return None


def get_feature_dim() -> int:
    """Return the number of features (for model validation)."""
    d = {
        "sender_email": "a@b.com", "sender_name": "", "subject": "", "body_text": "", "body_html": "",
        "links": [], "attachments": [], "auth_results": {}, "list_unsubscribe": "", "link_display_pairs": [],
        "reply_to_email": "",
    }
    v = extract_features(d)
    return len(v) if v else 0
