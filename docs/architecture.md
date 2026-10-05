# System Architecture & Dataflow Specification

## 1. High-Level Architecture Overview

The **Phishing Email Detection & Awareness Dashboard** is structured around a modular, multi-tier cybersecurity defense model. It ingests raw email components (headers, body text, extracted URLs, attachment filenames), performs heuristic and machine learning feature extraction, applies calibrated risk scoring, stores safe audit metadata, and presents explainable security assessments to analysts and end-users.

```
+-----------------------------------------------------------------------------------+
|                               USER / ANALYST LAYER                                |
|  - Web UI (Single Page Application, Tailwind CSS, Chart.js, Glassmorphism)         |
|  - REST API Clients / SIEM / Automated Ingestion Pipeline                         |
+-----------------------------------------+-----------------------------------------+
                                          | HTTP POST /api/analyze
                                          v
+-----------------------------------------------------------------------------------+
|                              FASTAPI INGESTION ENGINE                             |
|  - Request Validation & HTML Sanitization                                         |
|  - Token & Entity Extraction (EmailPreprocessor)                                  |
|  - Cross-Origin Resource Sharing (CORS) & Audit Event Logging                     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        PARALLEL DEFENSIVE ANALYSIS VECTORS                        |
|                                                                                   |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|  |  SENDER ANALYZER   |  |  CONTENT ANALYZER  |  |     STATIC URL ANALYZER     |  |
|  |  - Domain length   |  |  - Urgency & Fear  |  |  - Raw IP Hostnames         |  |
|  |  - Subdomain count |  |  - Financial cues  |  |  - High-risk TLDs (.zip)    |  |
|  |  - Typosquatting   |  |  - Credential ask  |  |  - Shorteners (bit.ly)      |  |
|  |  - Display mismatch|  |  - Generic greeting|  |  - Path credential keywords |  |
|  +--------------------+  +--------------------+  +-----------------------------+  |
|                                                                                   |
|  +--------------------------------+  +-----------------------------------------+  |
|  |      ATTACHMENT ANALYZER       |  |      MACHINE LEARNING INFERENCE         |  |
|  |  - Executables (.exe, .scr)    |  |  - TF-IDF N-grams (1,2) on subject/body |  |
|  |  - Double ext (.pdf.exe)       |  |  - Logistic Regression / Random Forest  |  |
|  |  - Macro files (.docm)         |  |  - Calibrated Phishing Probability %   |  |
|  +--------------------------------+  +-----------------------------------------+  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           HYBRID RISK SCORING ENGINE                              |
|  - Rule-Based Score (0 - 100) based on weighted security heuristics               |
|  - Machine Learning Probability Score (0 - 100%)                                  |
|  - Calibrated Ensemble Score: (55% Rules + 45% ML)                                |
|  - Classification: SAFE | LOW RISK | SUSPICIOUS | HIGH RISK / LIKELY PHISHING     |
|  - Explainability Engine: "WHY?" Bullets + Actionable SOC Recommendations         |
+-----------------------------------------+-----------------------------------------+
                                          |
                         +----------------+----------------+
                         |                                 |
                         v                                 v
+-----------------------------------+   +-------------------------------------------+
|          SQLITE DATABASE          |   |            FRONTEND DASHBOARD             |
|  - Safe Metadata (Domain, Subject)|   |  - Real-Time Risk Score Meter             |
|  - Indicator Severity Breakdown   |   |  - Color-Coded Classification Badge       |
|  - URL Findings & Audit Log       |   |  - Interactive "Before You Click" Guide   |
|  (Raw bodies omitted for privacy) |   |  - KPI Telemetry & Chart.js Trend Visuals |
+-----------------------------------+   +-------------------------------------------+
```

## 2. Ingestion & Preprocessing Phase

1. **Input Normalization**: Ingests `sender`, `display_name`, `subject`, `body`, `urls`, and `attachment_name`.
2. **Defensive Tokenization**: Preserves casing metrics, exclamation counts, and IP strings without aggressive stripping that would destroy attack artifacts.
3. **URL Parsing**: Automatically extracts URLs embedded in the body text using defensive regex patterns.

## 3. Analysis Vectors

- **Sender Vector**: Evaluates domain length, subdomain depth, and tests for character substitutions mimicking major brands (e.g. `paypa1`, `micr0soft`).
- **Content Vector**: Scans for social engineering triggers (urgency, threats of legal action or account suspension, financial pressure, credential verification requests).
- **URL Vector**: Performs deterministic string inspection. Checks for raw IP usage (`http://198.51.100.10`), URL shorteners, plain HTTP schemes, and authentication keywords in paths. **Never makes network requests or visits suspicious links.**
- **Attachment Vector**: Evaluates filename extensions, flags high-risk executables (`.exe`, `.scr`, `.bat`, `.vbs`) and deceptive double extensions (`.pdf.exe`). **Never executes attachments.**

## 4. Hybrid Scoring & Explainability

- The hybrid engine merges deterministic rule weights with statistical NLP probabilities.
- Explanations translate raw features into human-readable SOC findings (e.g., `[CRITICAL] Raw IP address used as hostname`).
- Provides tailored recommendations matching the specific vectors identified.
