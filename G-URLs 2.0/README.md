# G-URLs 2.0 — Multi-Layer Behavioural Detection Architecture

> **Masters Dissertation Project — Cybersecurity**  
> *A Multi-Layer Behavioural Detection Architecture for Malicious Domain and Web Traffic Analysis*

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![ML Models](https://img.shields.io/badge/ML%20Models-16%20trained-orange)
![Datasets](https://img.shields.io/badge/Samples-2.3M%20labelled-red)
![License](https://img.shields.io/badge/License-Academic-lightgrey)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Live Demo — Quickest Way to Run](#live-demo--quickest-way-to-run)
- [Architecture](#architecture)
- [Detection Modules](#detection-modules)
- [Datasets](#datasets)
- [ML Models](#ml-models)
- [Project Structure](#project-structure)
- [Installation — Full Setup](#installation--full-setup)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Research Results](#research-results)
- [Key Findings](#key-findings)
- [Technologies Used](#technologies-used)
- [Academic References](#academic-references)
- [Author](#author)

---

## Datasets

| Dataset | Source | Size | Module | Link |
| Zenodo CESNET-CIRA22 | CESNET Research Network | 530,468 domains | A (DNS), B (TLS) | [zenodo.org/records/14332167](https://zenodo.org/records/14332167) |
| CICIDS2017 | Canadian Institute for Cybersecurity, University of New Brunswick | 1,115,292 flows | C (Network) | [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) |
| PhiUSIIL | UCI ML Repository — Prasad & Chandra (2024) | 201,890 URLs | D (URL) | [archive.ics.uci.edu/dataset/967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) |
| ECU-MALNETT | Edith Cowan University Research Online | ~6M flows | Suitability assessment only | [ro.ecu.edu.au/datasets/151](https://ro.ecu.edu.au/datasets/151/) |

> **Note:** Datasets are not included in this repository due to size. Use the links above to download directly from the original sources. Pre-trained ML models are included in the `models/` directory and do not require dataset download to run the application.


## Project Overview

G-URLs 2.0 is the live artefact component of a Masters dissertation in Cybersecurity. It implements a **multi-layer behavioural detection architecture** that analyses any URL or domain across four independent detection layers simultaneously — producing a combined weighted risk verdict without relying on prior reputation databases.

Unlike traditional blacklist-based tools, G-URLs 2.0 detects threats through **behavioural and structural analysis** — meaning it can identify malicious URLs that have never been seen before (zero-day detection). Results are cross-referenced against VirusTotal threat intelligence and all four Phase 5 ML models for academic comparison.

### What Makes This Different

| Traditional Approach | G-URLs 2.0 |
|---|---|
| Checks known blacklists | Analyses behaviour and structure |
| Fails on new/unknown domains | Detects zero-day threats |
| Single signal detection | Four independent detection layers |
| No explanation of verdict | Shows every rule that fired |
| Reputation only | Behavioural + ML + Reputation |

### Evolution from G-URL (BSc Project)

G-URL (BSc, IBM X-Force integration) → **G-URLs 2.0** (Masters, original behavioural detection engine with ML and VirusTotal validation)

---

## Live Demo — Quickest Way to Run

> **For supervisors and examiners who want to run the application quickly without installing anything locally.**

### Option 1 — Google Colab (Recommended, Zero Installation)

Click the button below to open the project in Google Colab and run it in your browser:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/YOUR_GITHUB_USERNAME/gurls-2.0/blob/main/colab_demo.ipynb)

The Colab notebook will:
1. Install all dependencies automatically
2. Download pre-trained ML models
3. Launch the Flask app with a public URL via ngrok
4. Open G-URLs 2.0 in your browser — no local setup required

### Option 2 — One-Command Docker Run

If you have Docker installed:

```bash
docker run -p 5000:5000 YOUR_DOCKERHUB_USERNAME/gurls2:latest
```

Then open `http://localhost:5000` in your browser. Done.

### Option 3 — Local Installation (5 Minutes)

See [Installation](#installation--full-setup) section below.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Input: URL / Domain                   │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │               │
    ┌────▼────┐    ┌─────▼────┐   ┌─────▼────┐   ┌─────▼────┐
    │Module A │    │Module B  │   │Module C  │   │Module D  │
    │  DNS    │    │  TLS     │   │ Network  │   │  URL     │
    │ /18pts  │    │ /29pts   │   │ /29pts   │   │ /29pts   │
    └────┬────┘    └─────┬────┘   └─────┬────┘   └─────┬────┘
         │               │               │               │
         └───────────────┼───────────────┘               │
                         │                               │
              ┌──────────▼──────────┐                    │
              │  Normalise Scores   │◄───────────────────┘
              │  DNS×0.2419         │
              │  TLS×0.1257         │
              │  Net×0.2899         │
              │  URL×0.3424         │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   Combined Score    │
              │   0–1 Risk Scale    │
              └──────────┬──────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼────┐   ┌─────▼────┐
    │LOW RISK │    │ MEDIUM   │   │HIGH RISK │
    │  <0.15  │    │0.15-0.25 │   │  >0.25   │
    └─────────┘    └──────────┘   └──────────┘
```

---

## Detection Modules

### Module A — DNS Behaviour Analysis
- **Dataset:** Zenodo CESNET-CIRA22 (530,468 domains)
- **Features:** 28 DNS features — TTL, MX records, nameserver count, domain age, DNSSEC, IP alive ratio
- **Rules:** 18 weighted detection rules (max score: 18)
- **Rule-Based F1:** 0.675 | **Recall:** 0.903
- **Best ML F1:** Random Forest 0.941
- **Key Finding:** Malicious domains use aged domains deliberately to evade age-based detection

### Module B — TLS Metadata Analysis
- **Dataset:** Zenodo CESNET-CIRA22 (530,468 domains)
- **Features:** 19 TLS features — certificate issuer, CT log, validity duration, chain length, wildcard
- **Rules:** 10 weighted detection rules (max score: 29)
- **Rule-Based F1:** 0.359 | **Best ML F1:** Random Forest 0.774
- **Key Finding:** APT actors use legitimate certificates — infrastructure-layer detection insufficient alone

### Module C — Network Flow Behaviour Analysis
- **Dataset:** CICIDS2017 (1,115,292 flows, 14 attack categories)
- **Features:** 21 CICFlowMeter features — packet size, flow duration, TCP flags, bytes/s
- **Rules:** 9 weighted detection rules (max score: 29)
- **Rule-Based F1:** 0.828 | **Best ML F1:** Random Forest 0.999
- **Key Finding:** FIN flag frequency 5.93x higher in malicious flows

### Module D — URL Lexical Analysis
- **Dataset:** PhiUSIIL (201,890 URLs)
- **Features:** 26 URL structural features — length, similarity index, HTTPS, digit ratio, obfuscation
- **Rules:** 11 weighted detection rules (max score: 29)
- **Rule-Based F1:** 0.978 | **Best ML F1:** All models 1.000
- **Key Finding:** Expert rules approach theoretical ML performance limit (0.022 gap)

---

## Datasets

| Dataset | Source | Size | Module |
|---|---|---|---|
| Zenodo CESNET-CIRA22 | CESNET Research Network | 530,468 domains | A (DNS), B (TLS) |
| CICIDS2017 | Canadian Institute for Cybersecurity | 1,115,292 flows | C (Network) |
| PhiUSIIL | UCI ML Repository (Prasad & Chandra, 2024) | 201,890 URLs | D (URL) |
| ECU-MALNETT | Edith Cowan University | ~6M flows | Suitability assessment only |

> **Note:** Datasets are not included in this repository due to size. Download links are provided in the dissertation. Pre-trained ML models are included in the `models/` directory.

---

## ML Models

All 16 trained models are saved in the `URL Analyzer/models/` directory:

| Model | DNS F1 | TLS F1 | Network F1 | URL F1 |
|---|---|---|---|---|
| Logistic Regression | 0.780 | 0.689 | 0.883 | 1.000 |
| Decision Tree | 0.869 | 0.768 | 0.994 | 1.000 |
| Random Forest | 0.941 | 0.774 | 0.999 | 1.000 |
| XGBoost | 0.929 | 0.773 | 0.998 | 1.000 |

**Primary live prediction models:** Random Forest and XGBoost (tree-based, robust to feature scale differences in live deployment).

**Academic reference models:** Logistic Regression and Decision Tree (displayed for Phase 5 comparison, sensitive to feature distribution differences between dataset extraction and live deployment contexts).

### Important Note on rf_dns.pkl
The Random Forest DNS model is 435MB and may not be included 
in the repository due to GitHub file size limits.

If missing, download from: [your Google Drive link]
Place in: URL Analyzer/models/rf_dns.pkl

The application works without this file — DNS rule-based 
scoring and all other ML models remain fully functional. 
Only the DNS Random Forest ML prediction will show as 
unavailable.
---

## Project Structure

```
G-URLs-2.0/
│
├── URL Analyzer/                    # Main Flask application
│   ├── app.py                       # Flask backend, routes, VT integration
│   ├── scoring.py                   # All detection logic, ML predictions
│   ├── templates/
│   │   └── index.html               # Single-page frontend
│   ├── static/
│   │   ├── style.css                # Dark theme styling
│   │   └── script.js                # Frontend interaction logic
│   └── models/                      # Pre-trained ML models (16 files)
│       ├── lr_dns.pkl               # Logistic Regression — DNS
│       ├── dt_dns.pkl               # Decision Tree — DNS
│       ├── rf_dns.pkl               # Random Forest — DNS
│       ├── xgb_dns.pkl              # XGBoost — DNS
│       ├── lr_tls.pkl               # Logistic Regression — TLS
│       ├── dt_tls.pkl               # Decision Tree — TLS
│       ├── rf_tls.pkl               # Random Forest — TLS
│       ├── xgb_tls.pkl              # XGBoost — TLS
│       ├── lr_network.pkl           # Logistic Regression — Network
│       ├── dt_network.pkl           # Decision Tree — Network
│       ├── rf_network.pkl           # Random Forest — Network
│       ├── xgb_network.pkl          # XGBoost — Network
│       ├── lr_url.pkl               # Logistic Regression — URL
│       ├── dt_url.pkl               # Decision Tree — URL
│       ├── rf_url.pkl               # Random Forest — URL
│       ├── xgb_url.pkl              # XGBoost — URL
│       └── scaler_*.pkl             # StandardScalers for LR models
│
├── Dissertation Figures/            # All generated figures and tables
├── requirements.txt                 # Python dependencies
├── colab_demo.ipynb                 # Google Colab one-click demo
├── Dockerfile                       # Docker container configuration
└── README.md                        # This file
```

---

## Installation — Full Setup

### Prerequisites

- Python 3.10 or higher
- Anaconda (recommended) or pip
- Git

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/gurls-2.0.git
cd gurls-2.0
```

### Step 2 — Create Environment

**Using Anaconda (recommended):**

```bash
conda create -n gurls python=3.13
conda activate gurls
```

**Using venv:**

```bash
python -m venv gurls_env
source gurls_env/bin/activate        # Mac/Linux
gurls_env\Scripts\activate           # Windows
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

The `requirements.txt` file contains:

```
flask>=3.0.0
dnspython>=2.6.0
requests>=2.31.0
scikit-learn>=1.4.0
xgboost>=2.0.0
joblib>=1.3.0
numpy>=1.26.0
pandas>=2.2.0
urllib3>=2.0.0
```

### Step 4 — Add VirusTotal API Key

Open `URL Analyzer/app.py` and replace the placeholder:

```python
VT_API_KEY = "c87e9c848dd61198636e23d4fa12f5853da81361837f3f7578bddbdf6dfbe2a6"
```

> **Get a free API key at:** https://www.virustotal.com/gui/join-us  
> The free tier allows 4 requests per minute which is sufficient for demonstration.  
> The application works without a key — VirusTotal results will show as unavailable.

### Step 5 — Run the Application

```bash
cd "URL Analyzer"
python app.py
```

Open your browser at `http://localhost:5000`

---

## Configuration

### VirusTotal API Key
Required for reputation comparison. Free key available at virustotal.com. Without it, the VirusTotal panel shows N/A but all four detection modules and ML predictions work normally.

### ML Models
Pre-trained models are included in `models/`. If you need to retrain:

```bash
# Open retrain_models.ipynb in Jupyter
# Requires the original datasets (see Datasets section)
jupyter notebook retrain_models.ipynb
```

### Port Configuration
Default port is 5000. To change, edit the last line of `app.py`:

```python
app.run(debug=True, port=5000)  # Change 5000 to any available port
```

---

## Running the Application

### Normal Run

```bash
cd "URL Analyzer"
python app.py
```

### With Anaconda Prompt (Windows)

```
Start > Anaconda Prompt
cd "C:\path\to\URL Analyzer"
python app.py
```

### Expected Output

```
==================================================
  G-URLs 2.0 — Starting...
  Open browser: http://localhost:5000
==================================================
* Running on http://127.0.0.1:5000
* Debugger is active!
```

### Using the Application

1. Enter any URL in the input field — e.g. `https://www.google.com`
2. Click **Analyse** or press Enter
3. Wait 3-8 seconds for live DNS, TLS, and network checks
4. View results across:
   - **Four module cards** — individual scores and rules fired
   - **Extracted Features panel** — all raw feature values from the scan
   - **ML Prediction panel** — all four models per module
   - **VirusTotal panel** — industry reputation comparison
   - **Analysis History** — last 10 analyses

### Example URLs to Try

| URL | Expected Verdict |
|---|---|
| `https://www.google.com` | LOW RISK |
| `https://www.bbc.co.uk` | LOW RISK |
| `http://paypal-secure-verify.suspicious-login.xyz` | HIGH RISK |
| `http://192.168.1.1/admin/login` | HIGH RISK |

---

## Research Results

### Rule-Based Engine Performance

| Module | Dataset | F1 Score | Precision | Recall | Accuracy |
|---|---|---|---|---|---|
| A — DNS | Zenodo CESNET | 0.675 | 0.559 | 0.903 | 0.596 |
| B — TLS | Zenodo CESNET | 0.359 | 0.596 | 0.257 | 0.541 |
| C — Network | CICIDS2017 | 0.828 | 0.768 | 0.898 | 0.814 |
| D — URL | PhiUSIIL | 0.978 | 0.982 | 0.973 | 0.978 |

### ML vs Rule-Based F1 Comparison

| Module | Rule-Based | LR | DT | RF | XGBoost |
|---|---|---|---|---|---|
| DNS | 0.675 | 0.780 | 0.869 | 0.941 | 0.929 |
| TLS | 0.359 | 0.689 | 0.768 | 0.774 | 0.773 |
| Network | 0.828 | 0.883 | 0.994 | 0.999 | 0.998 |
| URL | 0.978 | 1.000 | 1.000 | 1.000 | 1.000 |

### Combined Scoring Weights

| Module | Standalone F1 | Weight | Max Score |
|---|---|---|---|
| A — DNS | 0.2419 | 0.2419 | 18 |
| B — TLS | 0.1257 | 0.1257 | 29 |
| C — Network | 0.2899 | 0.2899 | 29 |
| D — URL | 0.3424 | 0.3424 | 29 |

---

## Key Findings

### 1. Sophisticated Adversary Evasion
The combined DNS+TLS score gap between malicious and benign domains was only **0.0075 points** — demonstrating that APT-level adversaries systematically defeat infrastructure-layer detection through legitimate certificate and DNS configuration. This empirically validates the necessity of URL structural and network behavioural detection layers.

### 2. Module-Dependent ML Advantage
- **TLS benefits most** from ML — RF improved F1 from 0.359 to 0.774 (+0.415)
- **URL benefits least** — only 0.022 gap between expert rules (0.978) and perfect ML (1.000)
- Expert rules already approach theoretical ML limits for URL detection

### 3. Feature Importance Validates Rule Design
ML feature importance analysis independently confirmed that features assigned highest rule weights are precisely those all four ML models learn to prioritise — validating expert rule design through automated learning evidence.

### 4. Zero-Day Detection Demonstrated
During live demonstration, G-URLs 2.0 correctly classified a constructed phishing URL as **HIGH RISK — MALICIOUS** while VirusTotal returned **"NOT YET ANALYSED"** — demonstrating behavioural detection of threats unknown to reputation systems.

### 5. Recall Preservation
The DNS rule-based engine achieved higher recall (0.954) than Random Forest (0.932) despite lower aggregate F1 — reflecting deliberate recall-prioritisation in rule design appropriate for security contexts where missed threats carry asymmetric consequences.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.13 | Backend language |
| Flask | Web framework |
| dnspython | Live DNS resolution |
| ssl / socket | TLS certificate inspection |
| requests | Network connectivity probing |
| scikit-learn | ML models (LR, DT, RF) |
| XGBoost | Gradient boosting classifier |
| joblib | Model serialisation |
| numpy / pandas | Feature processing |
| HTML / CSS / JavaScript | Frontend |
| VirusTotal API v3 | Threat intelligence |

---

## Academic References

Key references underpinning the detection rules and architecture:

- Bilge et al. (2011) — EXPOSURE: Passive DNS analysis for malicious domain detection
- Anderson & McGrew (2016) — Encrypted malware traffic identification via TLS metadata
- Sharafaldin et al. (2018) — CICIDS2017 dataset and network flow detection
- Ma et al. (2009) — URL classification using lexical features
- Holz et al. (2008) — Fast-flux botnet measurement and detection
- Sommer & Paxson (2010) — Machine learning for network intrusion detection
- Mandiant (2022) — M-Trends: APT infrastructure investment practices
- Bilge & Dumitras (2012) — Zero-day attack empirical study
- Prasad & Chandra (2024) — PhiUSIIL Phishing URL Dataset

Full reference list available in the dissertation document.

---

## Troubleshooting

### App won't start
```bash
# Check Python version
python --version  # Must be 3.10+

# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Check models directory exists
ls "URL Analyzer/models/"
```

### DNS lookup errors
Some domains may timeout during DNS resolution. This is normal for domains that do not exist or block DNS queries. The app handles this gracefully and scores based on available signals.

### VirusTotal returns errors
Verify your API key is correctly set in `app.py`. The free tier has a rate limit of 4 requests/minute — wait a moment between analyses if you see 429 errors.

### ML models not loading
Ensure all `.pkl` files are present in the `models/` directory. If missing, run `retrain_models.ipynb` with the original datasets.

### Port already in use
```bash
# Change the port in app.py
app.run(debug=True, port=5001)
```

---

## Author

**Gbemisola**  
Masters in Cybersecurity  
Dissertation: *A Multi-Layer Behavioural Detection Architecture for Malicious Domain and Web Traffic Analysis*

---

## Acknowledgements

This project builds upon the following publicly available datasets released by their respective institutions for academic research:
- Zenodo CESNET-CIRA22 — CESNET research network
- CICIDS2017 — Canadian Institute for Cybersecurity
- PhiUSIIL — UCI Machine Learning Repository

---

*G-URLs 2.0 is an academic research artefact. It is designed for educational and research purposes only.*
