#!/usr/bin/env python3
"""
train_scanner_model.py — Train your own email threat model (no API key, no quota).

Advanced: cross-validation, gradient boosting, dynamic retrain (merge new data).

Usage:
  python train_scanner_model.py --data labelled_emails.json [--output ./trained_scanner.joblib]
  python train_scanner_model.py --data new_batch.json --append training_data.json --output trained_scanner.joblib  # dynamic: merge then train
  python train_scanner_model.py --data training_data.json --model gb --cv 5   # gradient boosting + 5-fold CV

Data format (JSON): [ { "email_data": { ... }, "label": "SAFE"|"THREAT" }, ... ]

After training, set in .env: AI_PROVIDER=local and TRAINED_MODEL_PATH=./trained_scanner.joblib
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Tuple

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
except ImportError:
    print("Install scikit-learn and joblib: pip install scikit-learn joblib")
    sys.exit(1)

from scanner_features import extract_features, get_feature_dim, FEATURE_VERSION

THREAT_LABELS = frozenset({"THREAT", "PHISHING", "SPAM", "SCAM", "SUSPICIOUS", "1", "malicious"})


def load_json_data(path: str) -> List[Tuple[Dict, int]]:
    """Load labelled samples from JSON. Returns list of (email_data, label 0/1)."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raw = [raw]
    samples = []
    for item in raw:
        email_data = item.get("email_data") or item
        label_str = (item.get("label") or item.get("verdict") or "SAFE").strip().upper()
        if label_str in THREAT_LABELS or label_str in ("PHISHING", "SPAM", "SCAM", "SUSPICIOUS"):
            label = 1
        else:
            label = 0
        # Ensure minimal keys for feature extraction
        if isinstance(email_data, dict):
            email_data.setdefault("links", [])
            email_data.setdefault("attachments", [])
            email_data.setdefault("auth_results", {})
            email_data.setdefault("list_unsubscribe", "")
            email_data.setdefault("link_display_pairs", [])
            email_data.setdefault("reply_to_email", "")
        samples.append((email_data, label))
    return samples


def load_csv_data(path: str) -> List[Tuple[Dict, int]]:
    """Load from CSV with columns: subject, body or body_text, sender_email, label."""
    import csv
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            subject = row.get("subject", "")
            body = row.get("body") or row.get("body_text", "")
            sender = row.get("sender_email", "")
            label_str = (row.get("label") or row.get("verdict") or "SAFE").strip().upper()
            label = 1 if label_str in THREAT_LABELS else 0
            email_data = {
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "links": [],
                "attachments": [],
                "auth_results": {},
                "list_unsubscribe": "",
                "link_display_pairs": [],
                "reply_to_email": "",
            }
            samples.append((email_data, label))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description="Train email threat classifier (advanced + dynamic)")
    parser.add_argument("--data", required=True, help="Path to labelled JSON or CSV")
    parser.add_argument("--append", default=None, help="Merge with this existing JSON dataset (dynamic retrain)")
    parser.add_argument("--output", default=None, help="Output model path (default: trained_scanner.joblib)")
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction for validation (default 0.2)")
    parser.add_argument("--max-depth", type=int, default=12, help="Tree max_depth (RF and GB)")
    parser.add_argument("--n-estimators", type=int, default=100, help="RF n_estimators or GB iterations")
    parser.add_argument("--model", choices=("rf", "gb"), default="rf", help="rf=RandomForest, gb=GradientBoosting (advanced)")
    parser.add_argument("--cv", type=int, default=0, help="Cross-validation folds (e.g. 5); 0=disabled")
    args = parser.parse_args()

    data_path = args.data
    if not os.path.isfile(data_path):
        print(f"Error: {data_path} not found")
        sys.exit(1)

    if data_path.lower().endswith(".csv"):
        samples = load_csv_data(data_path)
    else:
        samples = load_json_data(data_path)

    # Dynamic: merge with existing dataset
    if args.append and os.path.isfile(args.append):
        with open(args.append, "r", encoding="utf-8") as f:
            extra = json.load(f)
        if isinstance(extra, list):
            for item in extra:
                ed = item.get("email_data") or item
                lbl = (item.get("label") or item.get("verdict") or "SAFE").strip().upper()
                if isinstance(ed, dict):
                    ed.setdefault("links", [])
                    ed.setdefault("attachments", [])
                    ed.setdefault("auth_results", {})
                    ed.setdefault("list_unsubscribe", "")
                    ed.setdefault("link_display_pairs", [])
                    ed.setdefault("reply_to_email", "")
                samples.append((ed, 1 if lbl in THREAT_LABELS or lbl in ("PHISHING", "SPAM", "SCAM", "SUSPICIOUS") else 0))
        print(f"Merged with {args.append}: total {len(samples)} samples")

    if len(samples) < 20:
        print("Warning: Few samples. Recommend 100+ SAFE and 100+ THREAT for better accuracy.")

    X_list, y_list = [], []
    for email_data, label in samples:
        feat = extract_features(email_data)
        if feat is not None:
            X_list.append(feat)
            y_list.append(label)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list)
    n_threat = int(y.sum())
    n_safe = len(y) - n_threat
    print(f"Loaded {len(y)} samples: {n_safe} SAFE, {n_threat} THREAT (feature_dim={get_feature_dim()}, version={FEATURE_VERSION})")
    if len(y) < 10:
        print("Error: Too few valid samples after feature extraction.")
        sys.exit(1)

    # Cross-validation (advanced)
    if args.cv >= 2:
        skf = StratifiedKFold(n_splits=args.cv, shuffle=True, random_state=42)
        if args.model == "gb":
            clf_cv = HistGradientBoostingClassifier(max_depth=args.max_depth, random_state=42, class_weight="balanced")
        else:
            clf_cv = RandomForestClassifier(n_estimators=args.n_estimators, max_depth=args.max_depth, random_state=42, class_weight="balanced")
        scores = cross_val_score(clf_cv, X, y, cv=skf, scoring="f1")
        print(f"\n--- {args.cv}-fold CV F1: {scores.mean():.4f} (+/- {scores.std() * 2:.4f}) ---")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y if n_threat > 0 and n_safe > 0 else None
    )

    if args.model == "gb":
        clf = HistGradientBoostingClassifier(
            max_iter=args.n_estimators,
            max_depth=args.max_depth,
            random_state=42,
            class_weight="balanced",
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=15,
        )
    else:
        clf = RandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            random_state=42,
            class_weight="balanced",
        )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n--- Validation metrics ---")
    print(classification_report(y_test, y_pred, target_names=["SAFE", "THREAT"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    f1 = f1_score(y_test, y_pred, zero_division=0)
    print(f"F1 (binary): {f1:.4f}")

    out_path = args.output or os.path.join(os.path.dirname(__file__), "trained_scanner.joblib")
    obj = {
        "model": clf,
        "feature_dim": get_feature_dim(),
        "feature_version": FEATURE_VERSION,
        "metrics": {"f1": float(f1), "n_train": len(y_train), "n_test": len(y_test), "model_type": args.model},
    }
    joblib.dump(obj, out_path)
    print(f"\nModel saved to: {out_path}")
    print("Next: Set in .env  AI_PROVIDER=local  and  TRAINED_MODEL_PATH=" + out_path)


if __name__ == "__main__":
    main()
