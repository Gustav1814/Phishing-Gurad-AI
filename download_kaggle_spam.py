#!/usr/bin/env python3
"""
Convert a labeled spam/ham (or phishing) CSV into PhishGuard training format.

CSV must have a label column (e.g. "spam" 0/1 or "label"). Output is training_data.json
for supervised training. No extra deps for local CSV.

Usage:
  python download_kaggle_spam.py --csv emails.csv --output training_data.json
  python download_kaggle_spam.py   # download from Kaggle (requires kagglehub)
"""

import argparse
import csv
import json
import os
import re
import sys


def _find_csv(path: str):
    """Find first CSV file under path."""
    for root, _dirs, files in os.walk(path):
        for f in files:
            if f.lower().endswith(".csv"):
                return os.path.join(root, f)
    return None


def _normalize_label(val, col_name: str) -> str:
    """Map dataset label to SAFE or THREAT."""
    if val is None:
        return "SAFE"
    v = str(val).strip().upper()
    if v in ("0", "HAM", "LEGITIMATE", "NOT SPAM", "SAFE", "NO"):
        return "SAFE"
    if v in ("1", "SPAM", "PHISHING", "MALICIOUS", "THREAT", "YES"):
        return "THREAT"
    if col_name and "spam" in col_name.lower():
        return "THREAT" if v in ("1", "SPAM", "YES", "TRUE") else "SAFE"
    return "SAFE"


def _extract_links(text: str) -> list:
    if not text:
        return []
    return list(set(re.findall(r"https?://[^\s\)\]\"\']+", text)))


def _read_csv_rows(csv_path: str) -> list:
    """Read CSV with flexible encoding; return list of dict rows."""
    for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            with open(csv_path, "r", encoding=enc, newline="", errors="replace") as f:
                reader = csv.DictReader(f)
                cols = reader.fieldnames or []
                rows = []
                for row in reader:
                    if len(row) >= 1:
                        rows.append(row)
                return rows
        except (UnicodeDecodeError, csv.Error):
            continue
    raise ValueError(f"Could not read CSV: {csv_path}")


def convert_csv_to_training(csv_path: str, out_path: str) -> int:
    """
    Read labeled CSV and write training_data.json. Auto-detect columns:
    subject, body_plain/body/text/message, label/spam, from_address (optional).
    """
    rows = list(_read_csv_rows(csv_path))
    if not rows:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return 0
    cols = list(rows[0].keys())
    col_lower = {c.lower(): c for c in cols}

    # Subject
    sub_col = None
    for k in ("subject", "subject_line", "title", "header"):
        if k in col_lower:
            sub_col = col_lower[k]
            break
    if not sub_col and cols:
        sub_col = cols[0]

    # Body / message (prefer body content over raw_text when both exist, e.g. email_dataset_100k)
    body_col = None
    for k in ("body_plain", "body_text", "message", "body", "text", "content", "email", "email_body", "raw_text"):
        if k in col_lower:
            body_col = col_lower[k]
            break
    if not body_col:
        for c in cols:
            if c != sub_col and ("message" in c.lower() or "body" in c.lower() or "text" in c.lower()):
                body_col = c
                break
    if not body_col and len(cols) >= 2:
        body_col = cols[1]

    # Label column
    label_col = None
    for k in ("label", "category", "spam", "type", "class", "classification", "target"):
        if k in col_lower:
            label_col = col_lower[k]
            break
    if not label_col:
        for c in cols:
            if c.lower() in ("spam", "label", "category", "class"):
                label_col = c
                break
    if not label_col and len(cols) >= 3:
        label_col = cols[-1]
    if not label_col:
        raise ValueError("CSV must have a label column (e.g. spam, label, category).")

    # Optional: sender column (e.g. from_address in email_dataset_100k) for better features
    sender_col = None
    for k in ("from_address", "sender_email", "from", "email_from"):
        if k in col_lower:
            sender_col = col_lower[k]
            break
    # Optional: auth columns (spf_result, dkim_result, dmarc_result)
    auth_cols = {k: col_lower[k] for k in ("spf_result", "dkim_result", "dmarc_result") if k in col_lower}
    list_unsub_col = col_lower.get("list_unsubscribe")
    reply_to_col = col_lower.get("reply_to")

    # When CSV has only one content column (e.g. "text"), use first line as subject and full text as body
    single_text_col = sub_col and body_col and sub_col == body_col

    samples = []
    for row in rows:
        full_text = str(row.get(body_col or sub_col, "")).strip()[:5000]
        if sub_col and sub_col != (body_col or "") and not single_text_col:
            subject = str(row.get(sub_col, "")).strip()[:500]
        elif single_text_col and full_text:
            first_line = full_text.split("\n")[0].strip() if "\n" in full_text else full_text[:200]
            subject = (first_line[:500] if len(first_line) > 500 else first_line) or "No subject"
        else:
            subject = str(row.get(sub_col, "")).strip()[:500] if sub_col else "No subject"
        body = full_text
        if not body and not subject:
            continue
        label_val = str(row.get(label_col, "0")).strip()
        label = _normalize_label(label_val, label_col or "")
        links = _extract_links(body)
        sender = "noreply@example.com"
        if sender_col and row.get(sender_col):
            sender = str(row.get(sender_col, "")).strip()[:200]
        if not sender or "@" not in sender:
            sender = "unknown@spam-domain.com" if label == "THREAT" else "noreply@example.com"
        auth = {}
        if auth_cols:
            spf = str(row.get(auth_cols.get("spf_result", ""), "")).strip().lower()
            dkim = str(row.get(auth_cols.get("dkim_result", "") or "", "")).strip().lower()
            dmarc = str(row.get(auth_cols.get("dmarc_result", "") or "", "")).strip().lower()
            auth["spf"] = "pass" if spf == "pass" else ("fail" if spf == "fail" else "none")
            auth["dkim"] = "pass" if dkim == "pass" else ("fail" if dkim == "fail" else "none")
            auth["dmarc"] = "pass" if dmarc == "pass" else ("fail" if dmarc == "fail" else "none")
        list_unsub = str(row.get(list_unsub_col, "")).strip()[:500] if list_unsub_col else ""
        reply_to = str(row.get(reply_to_col, "")).strip()[:200] if reply_to_col else ""
        samples.append({
            "email_data": {
                "subject": subject,
                "sender_email": sender,
                "sender_name": "",
                "body_text": body,
                "body_html": str(row.get(col_lower.get("body_html", ""), "")).strip()[:5000] if "body_html" in col_lower else "",
                "links": links[:20],
                "attachments": [],
                "auth_results": auth,
                "list_unsubscribe": list_unsub,
                "link_display_pairs": [],
                "reply_to_email": reply_to,
            },
            "label": label,
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)
    return len(samples)


def main():
    parser = argparse.ArgumentParser(
        description="Download Kaggle spam dataset and convert to training_data.json"
    )
    parser.add_argument(
        "--dataset",
        default="jackksoncsie/spam-email-dataset",
        help="Kaggle dataset path (e.g. jackksoncsie/spam-email-dataset)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON path (default: data/training_data.json)",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Only convert an existing CSV (set KAGGLE_DATASET_PATH or pass --path)",
    )
    parser.add_argument(
        "--path",
        default=os.environ.get("KAGGLE_DATASET_PATH"),
        help="Path to already-downloaded dataset (folder containing CSV)",
    )
    parser.add_argument(
        "--csv",
        help="Use this local CSV file directly (e.g. emails.csv). Skips Kaggle download.",
    )
    args = parser.parse_args()
    if args.output is None:
        try:
            from config import DATA_DIR
            os.makedirs(DATA_DIR, exist_ok=True)
            args.output = os.path.join(DATA_DIR, "training_data.json")
        except ImportError:
            args.output = "training_data.json"

    csv_path = None
    if args.csv and os.path.isfile(args.csv):
        csv_path = args.csv
        print("Using local CSV:", csv_path)
    path = args.path
    if not csv_path and not args.no_download and not path:
        try:
            import kagglehub
        except ImportError:
            print("Install kagglehub: pip install kagglehub pandas")
            sys.exit(1)
        print(f"Downloading dataset: {args.dataset} ...")
        path = kagglehub.dataset_download(args.dataset)
        print("Path to dataset files:", path)

    if not csv_path:
        if not path or not os.path.isdir(path):
            print("Error: dataset path not found. Use --csv path/to/emails.csv for a local CSV, or run without --no-download to download from Kaggle.")
            sys.exit(1)
        csv_path = _find_csv(path)
        if not csv_path:
            print("Error: no CSV file found under", path)
            sys.exit(1)
        print("Using CSV:", csv_path)

    try:
        n = convert_csv_to_training(csv_path, args.output)
        print(f"Converted {n} samples -> {args.output}")
        print("Next: python train_and_check.py --data", args.output)
    except Exception as e:
        print("Conversion error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
