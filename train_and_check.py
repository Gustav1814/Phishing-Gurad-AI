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
import warnings

# Suppress unclosed sqlite3.Connection ResourceWarnings from sklearn/joblib during evaluation
warnings.filterwarnings("ignore", category=ResourceWarning, message="unclosed database")

# Default paths (production: data/ and models/)
try:
    from config import DATA_DIR, MODELS_DIR
    DEFAULT_DATA = os.path.join(DATA_DIR, "training_data.json")
    DEFAULT_MODEL = os.path.join(MODELS_DIR, "trained_scanner.joblib")
except ImportError:
    PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
    DEFAULT_DATA = os.path.join(PROJECT_DIR, "training_data.json")
    DEFAULT_MODEL = os.path.join(PROJECT_DIR, "trained_scanner.joblib")


def main():
    try:
        from config import ensure_dirs
        ensure_dirs()
    except ImportError:
        pass
    parser = argparse.ArgumentParser(description="Train the scanner model and check if it works")
    parser.add_argument("--data", default=DEFAULT_DATA, help=f"Labelled JSON (default: {os.path.basename(DEFAULT_DATA)})")
    parser.add_argument("--skip-eval", action="store_true", help="Save model and exit without running scanner on test set (saves 5–15 min)")
    args = parser.parse_args()

    if not os.path.isfile(args.data):
        print(f"Data file not found: {args.data}")
        print("Create training_data.json from CSV: python download_kaggle_spam.py --csv emails.csv --output training_data.json")
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
    if n_safe < 20 or n_threat < 20:
        print("  Tip: aim for at least 50 of each class for better accuracy.")

    # Split: 80% train, 20% test (so we check on emails the model never saw)
    stratify = y if n_threat > 0 and n_safe > 0 else None
    indices = np.arange(len(X))
    i_train, i_test = train_test_split(indices, test_size=0.2, random_state=42, stratify=stratify)
    X_train, X_test = X[i_train], X[i_test]
    y_train, y_test = y[i_train], y[i_test]
    test_email_data = [email_data_list[i] for i in i_test]
    n_train_safe = int(len(y_train) - y_train.sum())
    n_train_threat = int(y_train.sum())
    print(f"Training on {len(y_train)} emails ({n_train_safe} SAFE, {n_train_threat} THREAT), testing on {len(y_test)}...")

    # Balance classes by oversampling minority so the model learns both (stops "predict threat for everyone")
    rng = np.random.RandomState(42)
    i_safe_tr = np.where(y_train == 0)[0]
    i_threat_tr = np.where(y_train == 1)[0]
    if n_train_safe < n_train_threat and n_train_safe > 0:
        n_extra = n_train_threat - n_train_safe
        i_extra = rng.choice(i_safe_tr, size=n_extra, replace=True)
        X_train = np.vstack([X_train, X_train[i_extra]])
        y_train = np.concatenate([y_train, np.zeros(n_extra)])
        print(f"  Oversampled SAFE: training set now {len(y_train)} (balanced).")
    elif n_train_threat < n_train_safe and n_train_threat > 0:
        n_extra = n_train_safe - n_train_threat
        i_extra = rng.choice(i_threat_tr, size=n_extra, replace=True)
        X_train = np.vstack([X_train, X_train[i_extra]])
        y_train = np.concatenate([y_train, np.ones(n_extra)])
        print(f"  Oversampled THREAT: training set now {len(y_train)} (balanced).")

    # Stronger model: more trees and depth when we have enough data
    n_est = min(200, 50 + len(X_train) // 10)
    clf = RandomForestClassifier(n_estimators=n_est, max_depth=14, random_state=42, class_weight="balanced", min_samples_leaf=2)
    clf.fit(X_train, y_train)

    # Raw model accuracy (no scanner thresholds) — shows if the model itself is learning
    y_pred_raw = clf.predict(X_test)
    acc_raw = (y_pred_raw == y_test).mean()
    from sklearn.metrics import f1_score as sk_f1
    f1_raw = sk_f1(y_test, y_pred_raw, zero_division=0)
    print(f"  Raw model (on test set): accuracy {acc_raw:.0%}, F1 {f1_raw:.0%}")

    # Save model so the scanner can use it
    model_dir = os.path.dirname(DEFAULT_MODEL)
    if model_dir:
        os.makedirs(model_dir, exist_ok=True)
    obj = {
        "model": clf,
        "feature_dim": get_feature_dim(),
        "feature_version": FEATURE_VERSION,
        "metrics": {"f1": None, "n_train": len(y_train), "n_test": len(y_test), "model_type": "rf"},
    }
    joblib.dump(obj, DEFAULT_MODEL)
    print(f"Model saved to: {DEFAULT_MODEL}")

    if args.skip_eval:
        print("\n  (Skipped scanner evaluation — use without --skip-eval to run full check.)")
        print("  You can use the app with AI_PROVIDER=local in .env.")
        return

    # Force the scanner to use this model when we run the check
    os.environ["AI_PROVIDER"] = "local"
    os.environ["TRAINED_MODEL_PATH"] = DEFAULT_MODEL
    # So "via scanner" reflects only local model + thresholds (no adaptive feedback loop)
    os.environ["SCANNER_EVAL_MODE"] = "1"

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
    tp, fp, fn, tn = binary["tp"], binary["fp"], binary["fn"], binary["tn"]

    # Plain-language result
    print("\n" + "=" * 50)
    print("  RESULT: Is the model working?")
    print("=" * 50)
    print(f"  Raw model:   accuracy {acc_raw:.0%}, F1 {f1_raw:.0%}  (direct predictions)")
    print(f"  Via scanner: accuracy {accuracy:.0%}, F1 {f1:.0%}  (after thresholds)")
    print(f"  (TP={tp} FP={fp} FN={fn} TN={tn})")
    print()
    if f1 >= 0.85 and accuracy >= 0.85:
        status = "Working well"
        tip = "You can use the app with AI_PROVIDER=local in .env."
    elif f1 >= 0.70 or accuracy >= 0.80:
        status = "OK"
        tip = "Useable. For better results, add more labelled emails and run this again."
    else:
        status = "Needs improvement"
        tip = "Add more labelled data, then: python download_kaggle_spam.py --csv your.csv --output training_data.json && python train_and_check.py --data training_data.json"
    print(f"  >>> {status} <<<")
    print()
    print(f"  {tip}")
    print("=" * 50)


if __name__ == "__main__":
    main()
