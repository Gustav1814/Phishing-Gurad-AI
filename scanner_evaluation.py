"""
scanner_evaluation.py — Industry-standard accuracy metrics for the inbox scanner.

Given labelled samples (email_data + true verdict), runs the scanner and computes
precision, recall, F1 (binary: threat vs safe) and per-verdict metrics.
Use for tuning and to track accuracy over time.
"""

from typing import Any, Dict, List, Tuple

# Verdicts considered "threat" for binary metrics (align with adaptive_learning)
THREAT_VERDICTS = frozenset({"PHISHING", "SPAM", "SCAM", "SUSPICIOUS"})


def _normalize_verdict(v: str) -> str:
    return (v or "").strip().upper()


def evaluate(
    labelled_samples: List[Dict[str, Any]],
    analyze_fn: Any,
) -> Dict[str, Any]:
    """
    Run the analyzer on each sample and compute metrics.

    labelled_samples: list of { "email_data": {...}, "true_verdict": "SAFE"|"PHISHING"|... }
    analyze_fn: function(email_data) -> analysis dict with "verdict" and optionally "threat_score"

    Returns:
      - binary: precision, recall, f1, accuracy (threat vs non-threat)
      - per_verdict: for each true verdict, precision/recall/f1 when that class is positive
      - confusion: { "true_SAFE": {"pred_SAFE": n, "pred_PHISHING": n, ...}, ... }
      - sample_count, list of { true_verdict, pred_verdict, threat_score, correct }
    """
    results = []
    for item in labelled_samples:
        email_data = item.get("email_data")
        true_v = _normalize_verdict(item.get("true_verdict", ""))
        if not email_data:
            continue
        try:
            analysis = analyze_fn(email_data)
            pred_v = _normalize_verdict(analysis.get("verdict", ""))
            threat_score = analysis.get("threat_score", 0)
            true_threat = true_v in THREAT_VERDICTS
            pred_threat = pred_v in THREAT_VERDICTS
            results.append({
                "true_verdict": true_v,
                "pred_verdict": pred_v,
                "threat_score": threat_score,
                "true_threat": true_threat,
                "pred_threat": pred_threat,
                "correct": true_v == pred_v,
                "correct_binary": true_threat == pred_threat,
            })
        except Exception:
            continue

    n = len(results)
    if n == 0:
        return {
            "binary": {"precision": 0.0, "recall": 0.0, "f1": 0.0, "accuracy": 0.0},
            "per_verdict": {},
            "confusion": {},
            "sample_count": 0,
            "details": [],
        }

    # Binary: threat vs safe
    tp = sum(1 for r in results if r["true_threat"] and r["pred_threat"])
    fp = sum(1 for r in results if not r["true_threat"] and r["pred_threat"])
    fn = sum(1 for r in results if r["true_threat"] and not r["pred_threat"])
    tn = sum(1 for r in results if not r["true_threat"] and not r["pred_threat"])
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    acc = (tp + tn) / n

    # Confusion: true_verdict -> { pred_verdict: count }
    confusion: Dict[str, Dict[str, int]] = {}
    for r in results:
        t = r["true_verdict"] or "unknown"
        p = r["pred_verdict"] or "unknown"
        if t not in confusion:
            confusion[t] = {}
        confusion[t][p] = confusion[t].get(p, 0) + 1

    # Per-verdict metrics (one-vs-rest)
    all_true_verdicts = sorted(set(r["true_verdict"] for r in results))
    per_verdict = {}
    for v in all_true_verdicts:
        pos = [r for r in results if r["true_verdict"] == v]
        pred_pos = [r for r in results if r["pred_verdict"] == v]
        tp_v = sum(1 for r in results if r["true_verdict"] == v and r["pred_verdict"] == v)
        prec_v = tp_v / len(pred_pos) if pred_pos else 0.0
        rec_v = tp_v / len(pos) if pos else 0.0
        f1_v = 2 * prec_v * rec_v / (prec_v + rec_v) if (prec_v + rec_v) > 0 else 0.0
        per_verdict[v] = {"precision": round(prec_v, 4), "recall": round(rec_v, 4), "f1": round(f1_v, 4), "support": len(pos)}

    return {
        "binary": {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "accuracy": round(acc, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        },
        "per_verdict": per_verdict,
        "confusion": confusion,
        "sample_count": n,
        "details": results,
    }
