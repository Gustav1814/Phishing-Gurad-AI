# PhishGuard AI — Viva / Oral Exam Prep

Use this to answer confidently about **what the project does** and **the AI/ML ideas** behind it. Your teacher (PhD) will care that you understand the pipeline and the basics; you don’t need to go deep into theory you didn’t implement.

---

## 1. One-minute project summary (memorise this)

**“We built a phishing email detector. It’s a supervised learning system: we take labelled emails (safe vs threat), convert each email into a fixed set of numeric features, train a Random Forest classifier on 80% of the data, and test on the other 20%. The trained model is then used in a web app to score new emails and give a verdict (SAFE, SUSPICIOUS, PHISHING). We also have a rule-based fallback and an optional adaptive layer that learns from feedback.”**

---

## 2. Core AI/ML terms (use these in answers)

| Term | Plain meaning | In our project |
|------|----------------|----------------|
| **Supervised learning** | Learning from **labelled** data (each example has a correct answer). | We have emails labelled SAFE or THREAT; the model learns from those labels. |
| **Classification** | Predicting a **category** (not a number). | We predict: SAFE vs THREAT (binary classification). |
| **Features** | Numbers we extract from raw data so the model can learn. | We extract ~30 features per email (e.g. link count, keyword scores, SPF/DKIM, urgency signals). |
| **Feature extraction** | Turning raw email (text, headers, links) into a fixed-length vector of numbers. | `scanner_features.py`: same features for training and for live scanning. |
| **Train / test split** | Using part of the data to train, the rest to **evaluate** (to see if the model generalises). | We use 80% train, 20% test, with stratification so both sets have similar safe/threat ratio. |
| **Overfitting** | Model memorises training data and does badly on new data. | We avoid it by: (1) testing on held-out 20%, (2) not using the test set for training, (3) using Random Forest (many trees, less overfitting than a single deep tree). |
| **Random Forest** | Many decision trees trained on random subsets of data/features; final prediction = majority vote (or average probability). | We use scikit-learn’s `RandomForestClassifier`; no GPU needed, works well on our tabular features. |
| **Accuracy** | % of predictions that are correct. | We report it on the test set (e.g. 100% in your run). |
| **F1 score** | Balance of **precision** (when we say threat, how often we’re right) and **recall** (of all real threats, how many we catch). | We use it because we care about both false alarms and missed threats. |
| **Precision** | Of all emails we predicted as threat, how many were actually threat. | High precision = fewer false positives. |
| **Recall** | Of all real threats, how many we correctly flagged. | High recall = we don’t miss many threats. |
| **Inference** | Using the trained model to predict on **new** data. | When a user loads the app and scans an email, we run the same feature extraction and then the trained model predicts. |

---

## 3. Pipeline in 4 steps (say this if asked “how does it work?”)

1. **Data**  
   Labelled CSV (spam/ham or safe/threat) → we convert it to `training_data.json` (each item: email content + label).

2. **Features**  
   For each email we compute a fixed vector of ~30 numbers: sender/domain info, link counts, SPF/DKIM/DMARC, keyword counts (threat vs safe), urgency/BEC signals, attachment/link danger hints, etc. Same function for training and for live scanning.

3. **Training**  
   We take 80% of the data, balance classes by oversampling if needed, and train a **Random Forest** (many trees). We save the model to `models/trained_scanner.joblib`.

4. **Prediction**  
   For a new email we extract the same features, run the Random Forest, get a probability of “threat”. We map that to a verdict (SAFE / SUSPICIOUS / PHISHING) using configurable thresholds (e.g. score ≥ 65 → PHISHING).

---

## 4. Which file does what (where things happen)

| File | What happens here |
|------|--------------------|
| **`config.py`** | Paths (data/, models/, config/, instance/), verdict thresholds (e.g. PHISHING ≥ 65), env (AI_PROVIDER, TRAINED_MODEL_PATH). |
| **`scanner_features.py`** | **Feature extraction.** One function turns each email (subject, body, sender, links, auth, etc.) into a fixed list of ~30 numbers. Used by both training and the live scanner — same features, same order. |
| **`train_scanner_model.py`** | **Advanced training script.** Loads JSON/CSV → extracts features → train/test split → trains Random Forest (or gradient boosting with `--model gb`) → can do cross-validation (`--cv 5`) → saves model + prints validation metrics (F1, classification report, confusion matrix). |
| **`train_and_check.py`** | **Simple “train and check” pipeline.** Loads `training_data.json` → 80/20 split → optional class balancing (oversample minority) → trains Random Forest → computes **raw model** accuracy and F1 on test set → saves model → optionally runs **full scanner** on test emails and prints “via scanner” accuracy/F1 (calls `scanner_evaluation.evaluate`). |
| **`download_kaggle_spam.py`** | **Data preparation.** Reads a CSV (e.g. from Kaggle) with subject/body/sender/label → converts to our JSON format (`email_data` + `label`) → writes `training_data.json` (default: `data/training_data.json`). |
| **`inbox_scanner.py`** | **Live scanning / inference.** Loads the trained model (when AI_PROVIDER=local), extracts features for each email, runs the model to get threat probability, applies thresholds to output verdict (SAFE/SUSPICIOUS/PHISHING). Rule-based fallback if no model. Can connect to IMAP, parse auth (SPF/DKIM/DMARC), optional adaptive layer. |
| **`scanner_evaluation.py`** | **Where we compute all accuracy metrics.** Given labelled samples and the scanner function, it runs the scanner on each sample, then computes TP/FP/FN/TN, **precision**, **recall**, **F1**, **accuracy**, confusion counts, and per-verdict metrics. No training — only evaluation. |
| **`evaluate_accuracy.py`** | **CLI to measure scanner accuracy.** Loads a labelled JSON file, builds samples with `true_verdict`, calls `scanner_evaluation.evaluate()` with the real scanner, prints precision, recall, F1, accuracy, and TP/FP/FN/TN. Sets SCANNER_EVAL_MODE so adaptive layer is off during eval. |
| **`app.py`** | **Web app.** Flask routes: generate email, analyse email (calls inbox_scanner), evaluate API (body: samples with email_data + true_verdict → returns metrics from scanner_evaluation). Serves the frontend. |
| **`adaptive_learning.py`** | Optional layer: adjusts score using domain reputation and feedback. Disabled during evaluation (SCANNER_EVAL_MODE=1) so metrics reflect only the base model + thresholds. |
| **`threat_intel.py`** | Optional: checks sender domain against blocklists / threat intel. |
| **`scanner_config_loader.py`** | Loads scanner config (e.g. thresholds) from `config/` JSON. |
| **`indicator_engine.py`** | Rule-based indicators (e.g. “suspicious link”) shown in the UI. |
| **`email_generator.py`** | Generates sample phishing/safe emails for demo and training data. |
| **`email_sender.py`** | Sends emails (e.g. for testing or awareness campaigns). |

**Short “where” answers for viva:**

- **“Where do we extract features?”** → `scanner_features.py` — one function, same for training and scanning.
- **“Where do we train the model?”** → `train_scanner_model.py` (full options) or `train_and_check.py` (simple pipeline).
- **“Where do we compute accuracy and F1?”** → `scanner_evaluation.py` (the `evaluate()` function). It’s used by `train_and_check.py` (after training) and by `evaluate_accuracy.py` (standalone eval) and by the app’s evaluate API.
- **“Where does the app get the verdict for an email?”** → `inbox_scanner.py` (feature extraction + model prediction + thresholds).

---

## 5. Performance metrics — what they are and how we analyse our model

We treat the problem as **binary**: each email is either **threat** (PHISHING, SPAM, SCAM, SUSPICIOUS) or **safe** (SAFE). For every email we have:
- **True label** = what it really is (from our labelled data).
- **Predicted label** = what our scanner said (from the model + thresholds).

From that we count four numbers (all computed in **`scanner_evaluation.py`**):

| Abbreviation | Meaning | Plain English |
|--------------|---------|----------------|
| **TP** (True Positive) | We said threat, and it really was threat. | Correctly caught a bad email. |
| **FP** (False Positive) | We said threat, but it was actually safe. | False alarm — we wrongly flagged a good email. |
| **FN** (False Negative) | We said safe, but it was actually threat. | We missed a bad email. |
| **TN** (True Negative) | We said safe, and it really was safe. | Correctly left a good email as safe. |

**How we compute them (in code):**  
In `scanner_evaluation.py`, for each sample we compare `true_threat` (from true_verdict) and `pred_threat` (from scanner verdict). Then:
- TP = count where both true_threat and pred_threat are True  
- FP = count where true_threat False, pred_threat True  
- FN = count where true_threat True, pred_threat False  
- TN = count where both False  

**The four metrics we report:**

| Metric | Formula | Plain English | Why it matters |
|--------|--------|----------------|----------------|
| **Accuracy** | (TP + TN) / total | Of all emails, what fraction did we label correctly (either way)? | Overall correctness. Can be misleading if data is imbalanced (e.g. 99% safe). |
| **Precision** | TP / (TP + FP) | Of all emails we **said** were threat, how many were actually threat? | High precision = fewer false alarms (fewer FPs). |
| **Recall** | TP / (TP + FN) | Of all emails that **were** threat, how many did we catch? | High recall = we don’t miss many threats (fewer FNs). |
| **F1 score** | 2 × (precision × recall) / (precision + recall) | Single number that balances precision and recall. | We use F1 so we don’t only optimise accuracy; we care about both catching threats and not over-flagging safe mail. |

**Where each metric is computed and printed:**

- **`scanner_evaluation.py`** → `evaluate()` computes TP, FP, FN, TN then precision, recall, F1, accuracy. Returns them in the `binary` dict.
- **`train_and_check.py`** → After training, calls `evaluate()` on the test set and prints “Raw model” accuracy/F1 (from sklearn on 0/1 predictions) and “Via scanner” accuracy/F1 and TP/FP/FN/TN (from scanner_evaluation).
- **`evaluate_accuracy.py`** → Loads labelled data, calls `evaluate()`, prints precision, recall, F1, accuracy and TP/FP/FN/TN.
- **`train_scanner_model.py`** → Uses sklearn’s `f1_score`, `classification_report`, `confusion_matrix` on the **validation set** (not the full scanner). So here we analyse the **model alone** on 0/1 labels; the “via scanner” metrics (with thresholds) come from `scanner_evaluation` when we run `train_and_check.py` or `evaluate_accuracy.py`.

**One-line summary for viva:**  
“We analyse our model’s accuracy by running it on labelled data and comparing predicted vs true verdict. We count TP, FP, FN, TN in `scanner_evaluation.py`, then compute precision, recall, F1, and accuracy. We report both raw model metrics (during training) and ‘via scanner’ metrics (model + thresholds) so we know how the full system performs.”

---

## 6. Why these choices? (likely “why” questions)

- **Why Random Forest?**  
  “It works well on tabular, numeric features like ours; it doesn’t need a GPU; it’s interpretable (we can look at feature importance if we want); and it’s standard for this kind of classification in industry.”

- **Why these features?**  
  “We use domain/sender, links, auth (SPF/DKIM/DMARC), keyword counts for threat vs safe, urgency/BEC phrases, attachment and link risk, and a few more. They’re based on common phishing indicators and keep the pipeline simple and explainable.”

- **Why 80/20 split?**  
  “So we can measure performance on data the model never saw during training. Stratification keeps the same proportion of safe/threat in train and test.”

- **Why a rule-based fallback?**  
  “If the model isn’t loaded or fails, we still want to give a verdict using rules (keywords, links, attachments). It makes the system robust.”

- **Why F1 in addition to accuracy?**  
  “With imbalanced data, accuracy can be misleading. F1 balances precision and recall, so we care about both catching threats and not over-flagging safe mail.”

---

## 7. Likely questions and short answers

**Q: What type of machine learning is this?**  
A: Supervised learning, binary classification (safe vs threat).

**Q: What is the input and output of your model?**  
A: Input: a fixed-length feature vector (about 30 numbers) per email. Output: probability of threat (0–1), which we then map to SAFE / SUSPICIOUS / PHISHING using thresholds.

**Q: How do you convert an email to features?**  
A: We have a single feature-extraction function: it takes subject, body, sender, links, attachments, auth results, etc., and returns the same 30 numbers every time (e.g. link count, keyword scores, SPF/DKIM, urgency signals). Same function is used when training and when scanning in the app.

**Q: What is overfitting and how do you avoid it?**  
A: Overfitting is when the model memorises the training set and doesn’t generalise. We avoid it by (1) evaluating on a separate 20% test set, (2) not touching test data during training, and (3) using Random Forest, which is less prone to overfitting than a single complex tree.

**Q: What is the difference between training and inference?**  
A: Training is when we use labelled data to fit the model (learn the parameters). Inference is when we use the trained model to predict on new, unlabelled emails.

**Q: Why not use deep learning / neural networks?**  
A: “Our problem is well suited to tabular features and a Random Forest; we didn’t need a GPU or large dataset. We focused on a clean pipeline and rule-based fallback. Deep learning could be a future extension.”

**Q: What is precision and recall?**  
A: Precision: of all emails we predicted as threat, how many were actually threat. Recall: of all real threats, how many we correctly flagged. We use F1 to balance both.

**Q: What is the role of the threshold (e.g. 65)?**  
A: The model outputs a threat score (0–100). We compare it to thresholds (e.g. ≥65 → PHISHING, ≥40 → SUSPICIOUS, ≥22 → SPAM, else SAFE). These are configurable so we can tune for more or fewer false positives.

---

## 8. When you don’t know the answer

- **Stay calm.** Say one of these:
  - “I’m not sure about the theory; in the project we did X.”
  - “We didn’t go that deep; we used scikit-learn’s Random Forest and focused on the pipeline and the app.”
  - “I’d need to read more on that; our implementation was based on [feature extraction + train/test + thresholds].”

- **Redirect to what you did:**  
  “What I can explain is how our pipeline works: we label data, extract features, train a Random Forest, and then use it in the scanner with a rule-based fallback.”

- **Don’t invent** theory you’re unsure about. It’s better to say “I don’t know” or “we didn’t cover that” and then explain your project clearly.

---

## 9. Demo / “Show me” tips

- **Run training:**  
  `python train_and_check.py`  
  (uses `data/training_data.json`, saves to `models/trained_scanner.joblib`)

- **Run app:**  
  `python app.py`  
  Then: generate an email → Analyse → show the threat score and verdict.

- **Explain in one line:**  
  “The same features we use for training are extracted when you click Analyse; the trained model outputs a score, and we map it to SAFE or PHISHING using thresholds.”

---

## 10. Quick revision checklist

Before the viva, make sure you can say in your own words:

- [ ] What supervised learning and classification mean.
- [ ] What “features” are and that we use ~30 per email (and that `scanner_features.py` does this).
- [ ] Why we use a train/test split (to measure real performance).
- [ ] What Random Forest is (many trees, vote/average).
- [ ] What TP, FP, FN, TN mean and how we get precision, recall, F1, accuracy from them.
- [ ] That metrics are computed in `scanner_evaluation.py` and printed by `train_and_check.py` and `evaluate_accuracy.py`.
- [ ] The four steps: data → features → train → predict (and which files do each).
- [ ] That the same feature extraction is used in training and in the app.

Good luck. You know your project; this sheet helps you say it in AI/ML terms.
