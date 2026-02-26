#!/usr/bin/env python3
"""
evaluate_accuracy.py — Measure real accuracy of your scanner (trained model + rules + adaptive).

Run this on your labelled data to see precision, recall, F1. Use a hold-out set for honest
estimates (don't train on the same file you evaluate on).

Usage:
  python evaluate_accuracy.py --data training_data.json
  python evaluate_accuracy.py --data test_set.json   # best: use data you did NOT train on
"""

import argparse
import json
import os
import sys

# Convert label to true_verdict for the evaluation API
THREAT_LABELS = frozenset({"THREAT", "PHISHING", "SPAM", "SCAM", "SUSPICIOUS", "1", "malicious"})


def main():
    parser = argparse.ArgumentParser(description="Evaluate scanner accuracy on labelled data")
    parser.add_argument("--data", required=True, help="Labelled JSON (email_data + label)")
    parser.add_argument("--limit", type=int, default=0, help="Max samples to evaluate (0=all)")
    args = parser.parse_args()

    if not os.path.isfile(args.data):
        print(f"Error: {args.data} not found")
        sys.exit(1)

    with open(args.data, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raw = [raw]

    # Build samples in format expected by scanner_evaluation: email_data + true_verdict
    samples = []
    for item in raw:
        email_data = item.get("email_data") or item
        label = (item.get("label") or item.get("verdict") or "SAFE").strip().upper()
        if label in THREAT_LABELS or label in ("PHISHING", "SPAM", "SCAM", "SUSPICIOUS"):
            true_verdict = "PHISHING"  # any threat
        else:
            true_verdict = "SAFE"
        samples.append({"email_data": email_data, "true_verdict": true_verdict})

    if args.limit > 0:
        samples = samples[: args.limit]
    print(f"Evaluating {len(samples)} samples...")

    from inbox_scanner import analyze_email_with_ai
    from scanner_evaluation import evaluate

    metrics = evaluate(samples, analyze_email_with_ai)
    binary = metrics["binary"]
    print("\n--- Scanner accuracy (model + rules + adaptive) ---")
    print(f"  Precision:  {binary['precision']:.2%}")
    print(f"  Recall:     {binary['recall']:.2%}")
    print(f"  F1:         {binary['f1']:.2%}")
    print(f"  Accuracy:   {binary['accuracy']:.2%}")
    print(f"  (TP={binary['tp']}, FP={binary['fp']}, FN={binary['fn']}, TN={binary['tn']})")
    print("\nConfusion (true -> predicted):", metrics.get("confusion", {}))
    print("\nTo improve: add more labelled data, retrain, or correct via feedback API.")


if __name__ == "__main__":
    main()
