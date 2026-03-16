# 🛡️ AI Cyber Fraud Detector

A real-time fraud detection system for URLs and messages, combining Machine Learning, deterministic rule engines, and external threat intelligence APIs.

---

## Features

- **URL Analysis** — ML probability score + rule-based checks + optional VirusTotal & Google Safe Browsing integration
- **Message Analysis** — TF-IDF + SVM classifier to detect phishing/spam messages
- **Rule Engine** — Deterministic checks: HTTPS, IP hosts, suspicious keywords, Unicode/homoglyph attacks, download extensions
- **Verified Phishing Lookup** — Cross-references against a curated PhishTank-style dataset (`verified_online.csv`)
- **Whitelist Support** — Override verdicts for known-safe domains
- **Scan Logging** — All scans logged to `dataset/scan_log.csv` with full details
- **Calibrated ML** — Probability calibration with configurable decision threshold

---

## Project Structure

```
fraud_detection/
├── app.py                        # Streamlit web app
├── train_model.py                # Model training script
├── dataset/
│   ├── utils/
│   │   ├── url_features.py       # Feature extraction
│   │   ├── url_normalize.py      # URL canonicalization
│   │   ├── url_rules.py          # Deterministic rule engine
│   │   └── text_clean.py         # Message text preprocessing
│   ├── messages.csv              # Labeled messages for training
│   ├── urls.csv                  # Labeled URLs for training
│   ├── verified_online.csv       # Verified phishing URLs (PhishTank-style)
│   ├── whitelist.txt             # Known-safe domains
│   ├── forced_negatives.txt      # URLs forced as safe during training
│   └── scan_log.csv              # Runtime scan history
└── model/
    ├── url_model_calibrated.pkl  # Calibrated URL fraud model
    ├── url_model.pkl             # URL fraud model
    ├── text_model.pkl            # Message fraud model
    ├── vectorizer.pkl            # TF-IDF vectorizer
    └── url_model_calibration_info.json
```

---

## Tech Stack

| Component | Technology |
|---|---|
| UI | Streamlit |
| URL Model | Gradient Boosting / HistGradientBoosting / Logistic Regression (best selected) |
| Message Model | SVM (RBF kernel) + TF-IDF |
| External APIs | VirusTotal v3, Google Safe Browsing v4 |
| Language | Python 3 |

---

## Setup & Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/fraud_detection.git
cd fraud_detection

# Install dependencies
pip install streamlit scikit-learn pandas requests

# Train models (required before running the app)
python train_model.py

# Run the app
streamlit run app.py
```

---

## Usage

1. Open the app in your browser (default: `http://localhost:8501`)
2. **URL Check tab** — paste any URL and click *Scan Now*
   - Optionally enable VirusTotal or Google Safe Browsing checks
3. **Message Check tab** — paste a suspicious message and click *Scan Message*
4. **Analytics tab** — view session scan counts and recent scan logs

### Sidebar Options

- Adjust the ML fraud probability threshold (default: 0.5)
- Enter VirusTotal / Google Safe Browsing API keys
- Enable/disable scan logging
- Configure HTTP proxy and retry settings
- Switch to lightweight model for faster inference

---

## Model Training

```bash
python train_model.py
```

The training pipeline:
1. Loads `dataset/messages.csv` → trains SVM text classifier
2. Loads `dataset/verified_online.csv` (verified & online phishing URLs) as positives
3. Augments negatives from `dataset/urls.csv` + seed safe domains + path variants
4. Evaluates multiple candidate models (GB, HistGB, LogReg) and selects best by Brier score
5. Calibrates probabilities and saves all artifacts to `model/`

To limit training data for faster experiments:
```bash
python train_model.py --max-samples 5000
```

---

## How It Works

### URL Scoring (3-layer)

```
Final Score = 0.6 × ML_calibrated + 0.3 × Rule_score + 0.1 × Reputation_score
```

- **ML layer** — numeric feature vector (URL length, dots, hyphens, HTTPS, depth, keywords, IP flag, etc.) fed into a calibrated classifier
- **Rule layer** — deterministic checks produce a penalty score
- **Reputation layer** — VirusTotal / Google Safe Browsing results (optional)
- **Trusted override** — known-safe domains cap the final score at 10%

### Rule Engine Checks

| Type | Examples |
|---|---|
| Hard (high risk) | IP host, `@` in URL, punycode, suspicious file extension, Unicode anomalies |
| Soft (warning) | Missing HTTPS, suspicious keywords, excessive hyphens, deep subdomains |

---

## Customization

- **Add safe domains** → append to `dataset/whitelist.txt`
- **Force URLs as safe in training** → add to `dataset/forced_negatives.txt`
- **Add negative seed URLs** → add to `dataset/negatives_seed.csv`
- **API keys** — set via sidebar or environment variables `VT_API_KEY`, `GSB_API_KEY`

---

## Disclaimer

ML predictions are probabilistic and not 100% accurate. Always verify suspicious content through multiple sources. External checks depend on third-party API availability.

---

## License

MIT License
