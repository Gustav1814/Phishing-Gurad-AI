# PhishGuard AI

Phishing email generator and **inbox scanner** for security awareness training. Train on labeled spam/ham CSV; the model runs locally (no API key). Rule-based fallback, configurable thresholds, domain reputation and feedback.

---

## Project layout (production-ready)

```
Phishing-Gurad-AI/
  app.py              # Flask entry
  config.py            # Paths and env
  requirements.txt
  config/              # JSON configs (thresholds, rules, blocklist/allowlist)
  models/              # trained_scanner.joblib (created on train)
  data/                # training_data.json, CSVs (optional)
  instance/            # SQLite DBs (created at runtime)
  templates/
  static/
```

---

## Quick start

```bash
pip install -r requirements.txt
# 1) Convert CSV to training format
python download_kaggle_spam.py --csv your_emails.csv --output data/training_data.json
# 2) Train (saves model to models/trained_scanner.joblib)
python train_and_check.py --data data/training_data.json
# 3) Run app
python app.py
# Open http://localhost:5000
```

If your files are still in the project root: `python train_and_check.py --data training_data.json` — the model will be saved to `models/`. Scanner uses `models/trained_scanner.joblib` by default (`AI_PROVIDER=local`). No API keys needed.

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
| Convert CSV → training JSON | `python download_kaggle_spam.py --csv emails.csv --output training_data.json` |
| Train and check | `python train_and_check.py --data training_data.json` |
| Train only (skip 20k-email eval) | `python train_and_check.py --data training_data.json --skip-eval` |
| Evaluate on labelled data | `python evaluate_accuracy.py --data test_set.json` |
| Improve | Add more rows to your CSV (or merge into training_data.json), reconvert, then run `train_and_check.py` again |

- **Data:** Supervised learning. Use a CSV with a label column (spam/ham or 0/1). Aim for 50+ SAFE and 50+ THREAT (200+ each is better).
- **Metrics:** F1 &gt; 0.85 is good; use `evaluate_accuracy.py` on a hold-out set. Tune thresholds in `scanner_config.json` or via `POST /api/scanner/config` (no restart).
- **Dynamic:** Thresholds and rules are configurable at runtime. Feedback API updates domain reputation so the system improves with use.

---

## Dynamic config (no restart)

| What | How |
|------|-----|
| **Thresholds** | Edit `config/scanner_config.json` or `POST /api/scanner/config` with `{ "threshold_phishing": 65, "threshold_suspicious": 40, "threshold_spam": 22 }`. |
| **Rule keywords** | Edit `config/scanner_rules.json` or `POST /api/scanner/rules`. |
| **Allowlist / blocklist** | Edit `config/threat_intel.json` or `config/threat_intel_local.json`; or use `POST /api/threat-intel/allowlist`, `POST /api/threat-intel/blocklist`. Reload: `POST /api/threat-intel/reload`. |

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

## Deploy on Vercel (same behavior as local)

1. Connect the repo to Vercel and deploy.
2. In the project **Environment Variables** set:
   - **`AI_PROVIDER`** = `local` (use your trained model) or `custom` (use your HTTP AI) or `rules` (rule-based only).
   - **`SECRET_KEY`** = any random string (e.g. for sessions).
3. Check that the app and model are fine: open **`https://your-app.vercel.app/api/scanner/status`**. You want `local_model_working: true` when using the trained model.
4. **Persistent learning (optional):** By default, adaptive learning uses `/tmp` on Vercel, so scans/feedback don’t persist. To make learning persist across requests:
   - Add a Postgres DB (e.g. [Vercel Postgres](https://vercel.com/storage/postgres), Supabase, or Neon).
   - In Vercel env set **`DATABASE_URL`** (or **`POSTGRES_URL`**) to your `postgres://...` URL.
   - Uncomment **`psycopg2-binary`** in `requirements.txt` and redeploy. Scans and feedback will then be stored in Postgres and domain reputation will build over time.

---

## Key files

| Path | Purpose |
|------|---------|
| `app.py` | Flask app, API, UI. |
| `config.py` | Paths (config/, models/, data/, instance/), env. |
| `inbox_scanner.py` | Email analysis: local model, rules, adaptive layer. |
| `adaptive_learning.py` | Domain reputation, online learner, feedback. |
| `scanner_features.py` | Feature extraction for the trained model. |
| `download_kaggle_spam.py` | Convert CSV to training JSON. |
| `train_and_check.py` | One-shot train + test (writes to `models/`). |
| `train_scanner_model.py` | Advanced training (CV, GB). |
| `evaluate_accuracy.py` | Precision/recall/F1 on labelled JSON. |
| `config/scanner_config.json` | Dynamic thresholds. |
| `config/scanner_rules.json` | Extra rule keywords. |
| `config/threat_intel.json` | Allowlist/blocklist domains. |
| `config/threat_intel_local.json` | Your extra domains (merged). |

---

*For educational and awareness training use only.*
