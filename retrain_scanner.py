#!/usr/bin/env python3
"""
retrain_scanner.py — Dynamic retrain: merge new labelled data with existing set and train.

Use when you have new labelled emails (e.g. from feedback or manual review) and want to
retrain the model without losing previous data. Runs advanced training (CV optional, GB optional).

Usage:
  python retrain_scanner.py --new new_labelled.json [--base training_data.json] [--output trained_scanner.joblib]
  python retrain_scanner.py --new batch.json --base training_data.json --model gb --cv 5

If --base is omitted, only --new is used. Merged data is written to training_data_merged.json
(or you can pass --merged-out path). Then train_scanner_model is run on the merged file.
"""

import argparse
import json
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Merge new labelled data and retrain (dynamic)")
    parser.add_argument("--new", required=True, help="New labelled JSON (email_data + label)")
    parser.add_argument("--base", default=None, help="Existing training JSON to merge with")
    parser.add_argument("--merged-out", default=None, help="Path to write merged JSON (default: training_data_merged.json)")
    parser.add_argument("--output", default=None, help="Output model path (default: trained_scanner.joblib)")
    parser.add_argument("--model", choices=("rf", "gb"), default="rf", help="Model type")
    parser.add_argument("--cv", type=int, default=0, help="Cross-validation folds (0=off)")
    parser.add_argument("--max-depth", type=int, default=12)
    parser.add_argument("--n-estimators", type=int, default=100)
    args = parser.parse_args()

    if not os.path.isfile(args.new):
        print(f"Error: {args.new} not found")
        sys.exit(1)

    with open(args.new, "r", encoding="utf-8") as f:
        new_data = json.load(f)
    if not isinstance(new_data, list):
        new_data = [new_data]
    print(f"Loaded {len(new_data)} new samples from {args.new}")

    if args.base and os.path.isfile(args.base):
        with open(args.base, "r", encoding="utf-8") as f:
            base_data = json.load(f)
        if not isinstance(base_data, list):
            base_data = [base_data]
        merged = base_data + new_data
        print(f"Merged with {args.base}: {len(base_data)} + {len(new_data)} = {len(merged)} total")
    else:
        merged = new_data
        if args.base:
            print(f"Warning: {args.base} not found; using only --new")

    merged_path = args.merged_out or os.path.join(os.path.dirname(__file__), "training_data_merged.json")
    with open(merged_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    print(f"Merged data written to {merged_path}")

    out_path = args.output or os.path.join(os.path.dirname(__file__), "trained_scanner.joblib")
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "train_scanner_model.py"),
        "--data", merged_path,
        "--output", out_path,
        "--model", args.model,
        "--max-depth", str(args.max_depth),
        "--n-estimators", str(args.n_estimators),
    ]
    if args.cv >= 2:
        cmd.extend(["--cv", str(args.cv)])
    print("Running:", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        sys.exit(rc)
    print("Done. Model at", out_path)


if __name__ == "__main__":
    main()
