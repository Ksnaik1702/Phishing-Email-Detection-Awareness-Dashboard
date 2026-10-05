# Phishing Email Detection & Awareness Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E.svg)](https://scikit-learn.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.0%2B-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-25%2F25%20Passing-brightgreen.svg)](tests/)

> **Defensive Cybersecurity Dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.**

---

## Overview

Email remains the #1 initial access vector for cyber attacks globally. The **Phishing Email Detection & Awareness Dashboard** is a defensive, industry-oriented cybersecurity application designed to ingest emails, extract multi-vector threat signals, perform explainable heuristic and machine-learning risk scoring, and deliver interactive security awareness training.

Built for cybersecurity education, SOC analyst triage practice, and portfolio demonstration.

---

## Key Features

- **Multi-Vector Threat Analysis**: Evaluates Sender domains, Body content, Static URLs, and Attachment metadata.
- **Explainable Security Decisions**: Generates a 0–100 Risk Score, color-coded classification, and detailed "WHY?" reasoning bullets.
- **Actionable SOC Recommendations**: Context-aware defensive guidance (e.g. out-of-band verification, blocking URLs, reporting to SOC).
- **Hybrid Detection Model**: Blends deterministic rule-based heuristics with Scikit-Learn NLP models (TF-IDF + 19 structured features).
- **Safe Static URL Inspector**: Deep-dive analysis of raw IPs, URL shorteners, subdomains, and high-risk TLDs without visiting the destination.
- **Static Attachment Inspector**: Flags executables (`.exe`, `.scr`, `.bat`) and deceptive double extensions (`.pdf.exe`).
- **Interactive SOC Telemetry Dashboard**: Real-time KPI summary cards, classification doughnut charts, and 7-day ingestion trends using Chart.js.
- **Phishing Awareness Suite**: Interactive "Before You Click" hygiene checklist and 6 bite-sized security micro-lessons.
- **Audit History & Case Logging**: Privacy-preserving SQLite database storing analysis metadata without retaining sensitive raw email bodies.

---

## Architecture

```
Incoming Email (Sender, Subject, Body, URLs, Attachment)
                     │
                     ▼
             [ Preprocessor ] (Extracts URLs, casing metrics, domain tokens)
                     │
     ┌───────────────┼───────────────┬────────────────┬────────────────┐
     ▼               ▼               ▼                ▼                ▼
[ Sender ]      [ Content ]      [ URL ]       [ Attachment ]    [ ML Model ]
 (Domain,        (Urgency, Fear,  (Static IP,   (Extensions,     (TF-IDF +
  Lookalikes)     Credentials)    Shorteners)    Double-ext)      19 Features)
     └───────────────┬───────────────┴────────────────┴────────────────┘
                     ▼
           [ Hybrid Risk Engine ]
          (55% Rules + 45% ML Probability)
                     │
                     ▼
   [ Score (0-100) & Classification ]
   (SAFE | LOW RISK | SUSPICIOUS | HIGH RISK)
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  [ SQLite Audit ]      [ Web Dashboard ]
```

---

## Technology Stack

- **Backend API**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Machine Learning**: Scikit-Learn, Pandas, NumPy, Joblib, TF-IDF
- **Database**: SQLite3 (Thread-safe connection pooling)
- **Frontend**: Single Page Application (SPA), HTML5, Tailwind CSS, Font Awesome, Chart.js
- **Testing**: Python `unittest`, 25 automated security scenarios

---

## Installation & Local Setup

### Step 1: Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/Phishing-Email-Detection-Awareness-Dashboard.git
cd Phishing-Email-Detection-Awareness-Dashboard
```

### Step 2: Create & Activate Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Generate Synthetic Dataset & Train ML Model
```bash
python data/generate_dataset.py
python ml/train_model.py
```

### Step 5: Start the Application
```bash
python run_project.py
```

Open your browser and navigate to:
- **Interactive Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Swagger Interactive API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Running Automated Tests

Run the complete 25-scenario automated cybersecurity unit test suite:
```bash
python tests/test_comprehensive_25.py
```

### Test Suite Summary:
```
===============================================================================================
          AUTOMATED CYBERSECURITY TEST SUITE REPORT (25/25 SCENARIOS)          
===============================================================================================
ID     | Scenario                     | Expected           | Actual     | Status
-----------------------------------------------------------------------------------------------
TC-01  | Legitimate email             | SAFE/LOW RISK      | SAFE       | PASS  
TC-02  | Urgent phishing email        | HIGH/SUSPICIOUS    | HIGH RISK  | PASS  
TC-03  | Credential request detection | Credential = True  | True       | PASS  
TC-04  | Financial pressure detection | Financial = True   | True       | PASS  
TC-05  | Generic greeting detection   | Greeting = True    | True       | PASS  
TC-06  | Safe HTTPS URL inspection    | Risk Score <= 10   | Score: 0.0 | PASS  
TC-07  | Raw IP address in URL        | is_ip = True       | Score: 45.0| PASS  
TC-08  | Plain HTTP URL               | is_https = False   | False      | PASS  
TC-09  | Excessive subdomains URL     | subdomains >= 3    | 4          | PASS  
TC-10  | Suspicious keyword in URL    | Keyword found      | Found      | PASS  
TC-11  | Empty URL input              | Risk Score = 0     | Score: 0.0 | PASS  
TC-12  | Multiple URLs extraction     | url_count >= 2     | Count: 2   | PASS  
TC-13  | Normal PDF attachment        | Suspicious = False | False      | PASS  
TC-14  | Executable .exe attachment   | Executable = True  | Score: 40.0| PASS  
TC-15  | Double extension disguise    | is_double = True   | True       | PASS  
TC-16  | Empty subject check          | Handled gracefully | Handled    | PASS  
TC-17  | Empty body check             | Handled gracefully | Handled    | PASS  
TC-18  | Malformed sender address     | Handled gracefully | Handled    | PASS  
TC-19  | High uppercase ratio         | high_caps = True   | True       | PASS  
TC-20  | Multiple exclamation marks   | excessive = True   | True       | PASS  
TC-21  | Score boundary 0-100 check   | 0 <= Score <= 100  | Score: 0.0 | PASS  
TC-22  | SQLite database save         | Row in SQLite      | Found: True| PASS  
TC-23  | Lookalike domain validation  | Lookalike = True   | True       | PASS  
TC-24  | ML Model probability check   | 0.0 <= prob <= 1.0 | Prob: 0.90 | PASS  
TC-25  | Analysis history retrieval   | Count > 0          | Count: 3   | PASS  
===============================================================================================
[+] Total Tests: 25 | Passed: 25 | Failed: 0 | Success Rate: 100.00%
```

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Ingests email components and returns hybrid risk score, findings, and advice. |
| `POST` | `/api/analyze/url` | Dedicated static URL string risk inspector. |
| `GET` | `/api/analyses` | Retrieves historical analysis triage audit records (supports search & filters). |
| `GET` | `/api/analyses/{id}` | Returns comprehensive indicator breakdown for a specific analysis record. |
| `DELETE`| `/api/analyses/{id}` | Deletes an analysis record from audit history. |
| `GET` | `/api/dashboard/stats` | Aggregates summary KPIs, classification distribution, and 7-day trends. |
| `GET` | `/api/awareness/lessons`| Returns interactive micro-lessons and the "Before You Click" hygiene checklist. |
| `GET` | `/api/simulation/templates`| Returns safe pre-loaded synthetic templates for testing and demonstration. |

---

## MITRE ATT&CK Mapping

This project maps directly to the following **MITRE ATT&CK Enterprise Matrix** techniques:
- **T1566 (Phishing)**: Detected via social engineering triggers in subject and body.
- **T1566.001 (Spearphishing Attachment)**: Detected via static inspection of filenames and double extensions (`.pdf.exe`).
- **T1566.002 (Spearphishing Link)**: Detected via static inspection of raw IPs, shortened URLs, and deceptive paths.
- **T1566.003 (Spearphishing via Service)**: Detected via lookalike brand checks and display name mismatches.
- **T1204 (User Execution)**: Mitigated via interactive "Before You Click" checklists and user training modules.

---

## Security & Privacy Safeguards

- **No Network Requests to Suspicious Links**: URLs are analyzed strictly as static text strings without DNS lookups or HTTP calls.
- **No Attachment Execution**: Files are analyzed via metadata and extension patterns.
- **Privacy-Preserving Storage**: Raw email bodies are never permanently stored in the database.
- **Strictly Synthetic Data**: All training data, domains (`.invalid.test`, `example.com`), and IPs (`198.51.100.x`) use RFC-reserved test ranges.

---

## Disclaimer

> **EDUCATIONAL & DEFENSIVE USE ONLY**: This project is designed strictly for cybersecurity education, academic coursework, defensive engineering, and security awareness training. It uses synthetic test data and does not send live phishing emails, harvest credentials, or execute malware.

---

## Author

- **GitHub**: [github.com/YOUR_USERNAME](https://github.com/YOUR_USERNAME)
- **LinkedIn**: [linkedin.com/in/YOUR_PROFILE](https://linkedin.com/in/YOUR_PROFILE)
- **Project Repository**: `Phishing-Email-Detection-Awareness-Dashboard`
