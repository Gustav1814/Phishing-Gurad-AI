#!/usr/bin/env python3
"""
generate_training_data.py — Generate labelled training data for the scanner model.

Creates SAFE and THREAT examples so you can train without collecting real emails.
Usage:
  python generate_training_data.py --safe 100 --threat 100 --output training_data.json

For companies: add your own labelled exports to the JSON, then train.
"""

import argparse
import json
import random
import os

SAFE_TEMPLATES = [
    {"subject": "Your order has shipped", "sender": "orders@amazon.com", "name": "Amazon", "body": "Track your package. You requested this email. Unsubscribe from shipping updates."},
    {"subject": "New connection request on LinkedIn", "sender": "notifications@linkedin.com", "name": "LinkedIn", "body": "You have a new connection request. View it here. Unsubscribe in settings."},
    {"subject": "Password reset request", "sender": "noreply@github.com", "name": "GitHub", "body": "You requested a password reset. If this was you, click the link. Unsubscribe from security emails."},
    {"subject": "Invoice #INV-2024-001", "sender": "billing@stripe.com", "name": "Stripe", "body": "Your invoice is ready. View in dashboard. You can unsubscribe from billing emails."},
    {"subject": "Calendar: Meeting tomorrow 10am", "sender": "calendar@google.com", "name": "Google Calendar", "body": "You have an upcoming meeting. View in Calendar. Reply to this email to respond."},
    {"subject": "Your subscription renewal", "sender": "billing@netflix.com", "name": "Netflix", "body": "Your plan renews next month. Update payment method. Unsubscribe from billing."},
]

THREAT_TEMPLATES = [
    {"subject": "Verify your account - suspended", "sender": "support@paypa1-secure.com", "name": "PayPal Support", "body": "Your account has been suspended. Click here to verify your identity. Act now within 24 hours or your account will be closed. Enter your credentials to confirm."},
    {"subject": "Urgent: Wire transfer required", "sender": "ceo@gmail.com", "name": "David CEO", "body": "I need you to process a wire transfer to our new vendor. Confidential. Send payment to the new bank account. As per our CEO request."},
    {"subject": "You won $1,000,000 - claim now", "sender": "winner@lottery-intl.com", "name": "International Lottery", "body": "Congratulations! You are the beneficiary of a million dollars. Wire a small fee to release the funds. Next of kin must respond. Bitcoin opportunity."},
    {"subject": "Your device is infected - call now", "sender": "security@microsoft-support.com", "name": "Microsoft Support", "body": "Your computer has been compromised. Call this number immediately for tech support. Virus detected. Remote access required to fix."},
    {"subject": "Confirm your identity", "sender": "no-reply@amaz0n-account.com", "name": "Amazon", "body": "We could not verify your account. Click here to confirm your identity and update your password. Sign in to confirm. Last warning."},
    {"subject": "Final notice - account terminated", "sender": "billing@chase-secure.com", "name": "Chase Bank", "body": "Failure to comply will result in account termination. Verify your login within 2 hours. Unauthorized access detected. Act now."},
]


def make_safe_sample(template: dict, seed: int) -> dict:
    t = template.copy()
    random.seed(seed)
    body = t["body"] + " " * random.randint(0, 50)
    return {
        "email_data": {
            "subject": t["subject"],
            "sender_email": t["sender"],
            "sender_name": t["name"],
            "body_text": body,
            "links": ["https://www." + t["sender"].split("@")[1].replace(".com", ".com/")],
            "attachments": [],
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "list_unsubscribe": "<mailto:unsub@example.com>",
            "link_display_pairs": [],
            "reply_to_email": "",
        },
        "label": "SAFE",
    }


def make_threat_sample(template: dict, seed: int) -> dict:
    t = template.copy()
    random.seed(seed)
    body = t["body"] + " " * random.randint(0, 30)
    links = ["https://bit.ly/" + str(seed)[:6]] if random.random() > 0.3 else []
    auth = {"spf": "fail", "dkim": "none", "dmarc": "none"} if random.random() > 0.2 else {"spf": "none", "dkim": "none", "dmarc": "none"}
    return {
        "email_data": {
            "subject": t["subject"],
            "sender_email": t["sender"],
            "sender_name": t["name"],
            "body_text": body,
            "links": links,
            "attachments": [],
            "auth_results": auth,
            "list_unsubscribe": "",
            "link_display_pairs": [],
            "reply_to_email": "other@evil.com" if random.random() > 0.5 else "",
        },
        "label": "THREAT",
    }


def main():
    parser = argparse.ArgumentParser(description="Generate labelled training data for scanner model")
    parser.add_argument("--safe", type=int, default=50, help="Number of SAFE samples")
    parser.add_argument("--threat", type=int, default=50, help="Number of THREAT samples")
    parser.add_argument("--output", default="training_data.json", help="Output JSON path")
    args = parser.parse_args()

    samples = []
    for i in range(args.safe):
        t = SAFE_TEMPLATES[i % len(SAFE_TEMPLATES)]
        samples.append(make_safe_sample(t, i))
    for i in range(args.threat):
        t = THREAT_TEMPLATES[i % len(THREAT_TEMPLATES)]
        samples.append(make_threat_sample(t, args.safe + i))

    random.seed(42)
    random.shuffle(samples)

    out_path = args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)
    print(f"Generated {len(samples)} samples: {args.safe} SAFE, {args.threat} THREAT -> {out_path}")
    print("Next: python train_scanner_model.py --data", out_path)


if __name__ == "__main__":
    main()
