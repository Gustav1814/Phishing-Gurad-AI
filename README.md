# PhishGuard AI

AI-driven phishing email generator and **inbox scanner** for security awareness training. Generates simulations and analyzes real emails for threats (phishing, BEC, spam, scams). Uses Gemini (optional), your own trained model, or a custom HTTP AI — no API key required for local/custom.

---

## Quick start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

**Use your own model (no Gemini):**

1. `python train_and_check.py` — trains on `training_data.json`, saves `trained_scanner.joblib`, prints if it’s working.
2. In `.env` set `AI_PROVIDER=local`.
3. Restart the app. Scanner uses your model.

---

## How scoring works (domain score → content/attachments)

1. **Domain score (reputation)** — From scan history: how often this sender was SAFE vs THREAT (and feedback). If the domain has enough safe history (e.g. 3+ scans, mostly safe), we treat it as trusted and **cap** the score so legitimate mail isn’t over-flagged.
2. **Content and attachments** — Links, keywords, BEC/urgency, attachment types, etc. drive the base score. We always check content/attachments; domain score only decides whether we cap when the sender is trusted.
3. **Allowlist** — For senders with **no history** yet (e.g. first time you see gamma.app). Once a domain has good reputation, domain score handles it; you don’t need to add it to the allowlist.

So: **domain score first**, then **content/attachments** for spam/phishing. Allowlist = backup for known-good senders before they have reputation.

---

## Training & accuracy

| Goal | Command / action |
|------|-------------------|
| Train and check | `python train_and_check.py` |
| Evaluate on labelled data | `python evaluate_accuracy.py --data test_set.json` |
| Improve | Add more labelled SAFE/THREAT to `training_data.json`, run `train_and_check.py` again |

- **Data:** Aim for 50+ SAFE and 50+ THREAT (200+ each is better). Real labelled emails improve accuracy most.
- **Metrics:** F1 &gt; 0.85 is good; use `evaluate_accuracy.py` on a hold-out set. Tune thresholds in `scanner_config.json` or via `POST /api/scanner/config`.
- **Feedback:** When the scanner is wrong, call the feedback API with the correct verdict so domain reputation and the online learner adapt.

---

## Dynamic config (no restart)

| What | How |
|------|-----|
| **Thresholds** | Edit `scanner_config.json` or `POST /api/scanner/config` with `{ "threshold_phishing": 65, "threshold_suspicious": 40, "threshold_spam": 22 }`. |
| **Rule keywords** | Edit `scanner_rules.json` or `POST /api/scanner/rules` with `{ "bec_patterns": ["..."], "urgency": ["..."], ... }`. |
| **Allowlist / blocklist** | Edit `threat_intel.json` or `threat_intel_local.json`; or `POST /api/threat-intel/allowlist` (body `{ "domain": "example.com" }`), `POST /api/threat-intel/allowlist/bulk` (body `{ "domains": ["a.com", "b.com"] }`), `POST /api/threat-intel/blocklist`. Reload: `POST /api/threat-intel/reload`. |

Model blend (static + online learner) and domain reputation update automatically from scans and feedback.

---

## Custom AI endpoint

Use your own model over HTTP. In `.env`:

```env
AI_PROVIDER=custom
CUSTOM_AI_URL=http://localhost:8000/analyze
CUSTOM_AI_API_KEY=optional_bearer_token
CUSTOM_AI_TIMEOUT=30
```

**Request:** POST JSON with `subject`, `sender_email`, `body_text`, `links`, `attachments`, `auth_results`, etc.

**Response:** JSON with at least `verdict` (`SAFE`|`SUSPICIOUS`|`PHISHING`|`SPAM`|`SCAM`) and `threat_score` (0–100).

---

## Key files

| File | Purpose |
|------|---------|
| `app.py` | Flask app, API, UI. |
| `inbox_scanner.py` | Email analysis: local model, rules, adaptive layer. |
| `adaptive_learning.py` | Domain reputation, similar-past, online learner, feedback. |
| `scanner_features.py` | Feature extraction for the trained model. |
| `train_and_check.py` | One-shot train + test; use this first. |
| `train_scanner_model.py` | Advanced training (CV, GB, merge data). |
| `evaluate_accuracy.py` | Measure precision/recall/F1 on labelled JSON. |
| `scanner_config.json` | Dynamic thresholds. |
| `scanner_rules.json` | Extra rule keywords (merged with built-in). |
| `threat_intel.json` | Allowlist/blocklist domains. |
| `threat_intel_local.json` | Your extra domains (merged). |

---

*For educational and awareness training use only.*
