#!/usr/bin/env python3
"""
Train the model and check if it's working — one command, no ML knowledge needed.

  python train_and_check.py

Uses training_data.json (or --data your_file.json). Trains on 80% of the data,
tests on 20%, and prints a simple result: "Working", "OK", or "Add more data".
Saves the model so the app can use it (set AI_PROVIDER=local in .env).
"""

import argparse
import os
import sys

# Default paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA = os.path.join(PROJECT_DIR, "training_data.json")
DEFAULT_MODEL = os.path.join(PROJECT_DIR, "trained_scanner.joblib")


def main():
    parser = argparse.ArgumentParser(description="Train the scanner model and check if it works")
    parser.add_argument("--data", default=DEFAULT_DATA, help=f"Labelled JSON (default: {os.path.basename(DEFAULT_DATA)})")
    args = parser.parse_args()

    if not os.path.isfile(args.data):
        print(f"Data file not found: {args.data}")
        print("Create training_data.json with your labelled emails, or run: python generate_training_data.py")
        sys.exit(1)

    # Load and prepare data (same format as train_scanner_model)
    from train_scanner_model import load_json_data, THREAT_LABELS
    from scanner_features import extract_features, get_feature_dim, FEATURE_VERSION

    try:
        import joblib
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import f1_score
    except ImportError:
        print("Missing packages. Run: pip install scikit-learn joblib")
        sys.exit(1)

    samples = load_json_data(args.data)
    if len(samples) < 20:
        print(f"Only {len(samples)} samples. Add more labelled emails (aim for 50+ SAFE and 50+ THREAT) and run again.")
        sys.exit(1)

    X_list, y_list, email_data_list = [], [], []
    for email_data, label in samples:
        feat = extract_features(email_data)
        if feat is not None:
            X_list.append(feat)
            y_list.append(label)
            email_data_list.append(email_data)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list)
    n_safe = int(len(y) - y.sum())
    n_threat = int(y.sum())
    print(f"Using {len(y)} emails: {n_safe} SAFE, {n_threat} THREAT")

    # Split: 80% train, 20% test (so we check on emails the model never saw)
    stratify = y if n_threat > 0 and n_safe > 0 else None
    indices = np.arange(len(X))
    i_train, i_test = train_test_split(indices, test_size=0.2, random_state=42, stratify=stratify)
    X_train, X_test = X[i_train], X[i_test]
    y_train, y_test = y[i_train], y[i_test]
    test_email_data = [email_data_list[i] for i in i_test]
    print(f"Training on {len(y_train)} emails, testing on {len(y_test)} emails...")

    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    # Save model so the scanner can use it
    obj = {
        "model": clf,
        "feature_dim": get_feature_dim(),
        "feature_version": FEATURE_VERSION,
        "metrics": {"f1": None, "n_train": len(y_train), "n_test": len(y_test), "model_type": "rf"},
    }
    joblib.dump(obj, DEFAULT_MODEL)
    print(f"Model saved to: {os.path.basename(DEFAULT_MODEL)}")

    # Force the scanner to use this model when we run the check
    os.environ["AI_PROVIDER"] = "local"
    os.environ["TRAINED_MODEL_PATH"] = DEFAULT_MODEL

    # Run the real scanner (with this model) on the test emails
    from inbox_scanner import analyze_email_with_ai
    from scanner_evaluation import evaluate

    test_samples = []
    for i, ed in enumerate(test_email_data):
        true_v = "PHISHING" if y_test[i] == 1 else "SAFE"
        test_samples.append({"email_data": ed, "true_verdict": true_v})

    metrics = evaluate(test_samples, analyze_email_with_ai)
    binary = metrics["binary"]
    f1 = binary["f1"]
    accuracy = binary["accuracy"]

    # Plain-language result
    print("\n" + "=" * 50)
    print("  RESULT: Is the model working?")
    print("=" * 50)
    print(f"  Accuracy:  {accuracy:.0%}  (correct verdicts on test emails)")
    print(f"  F1 score:  {f1:.0%}  (balance of catching threats vs false alarms)")
    print()
    if f1 >= 0.85 and accuracy >= 0.85:
        status = "Working well"
        tip = "You can use the app with AI_PROVIDER=local in .env."
    elif f1 >= 0.70 or accuracy >= 0.80:
        status = "OK"
        tip = "Useable. For better results, add more labelled emails and run this again."
    else:
        status = "Needs improvement"
        tip = "Add more labelled SAFE and THREAT emails to training_data.json and run again."
    print(f"  >>> {status} <<<")
    print()
    print(f"  {tip}")
    print("=" * 50)


if __name__ == "__main__":
    main()
