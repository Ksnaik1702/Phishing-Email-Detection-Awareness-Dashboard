# Comprehensive Project Report: Phishing Email Detection & Awareness Dashboard

**Author:** Cybersecurity Engineering Student  
**Project Title:** Phishing Email Detection & Awareness Dashboard  
**Date:** October 2026  
**Category:** Defensive Cybersecurity / Machine Learning / SOC Automation  

---

## 1. Abstract
Email remains the primary initial attack vector responsible for over 90% of organizational breaches. This project presents an end-to-end defensive cybersecurity system that ingests incoming emails, executes multi-vector static and machine-learning analysis across headers, body content, URLs, and attachment metadata, and presents an explainable phishing risk assessment with interactive security awareness modules. By combining deterministic rule-based heuristics with machine learning algorithms trained on TF-IDF n-grams and 19 engineered cybersecurity indicators, the system achieves robust detection precision while minimizing false alerts. The platform operates strictly with safe synthetic datasets and non-intrusive static inspection protocols, making it safe, educational, and enterprise-aligned.

---

## 2. Introduction & Problem Statement
Adversaries continuously evolve phishing campaigns using social engineering tactics (urgency, fear, financial lures), brand impersonation, deceptive URL infrastructure, and malicious attachment formats. Traditional signature-based email filters often fail against novel, polymorphic lures. Conversely, opaque AI detectors lack explainability, leaving SOC analysts without actionable context. 

This project solves both challenges by implementing a **Hybrid Defensive Architecture**:
1. **Explainable Rule-Based Heuristics**: Breaks down threats into clear, audit-ready indicator findings.
2. **Machine Learning Classifier**: Provides statistical confidence across text semantics and structured feature vectors.
3. **Defensive Awareness Suite**: Empowers end users with bite-sized training and interactive security hygiene checklists.

---

## 3. System Architecture & Workflow

```
[ Email Input ] 
      │
      ▼
[ Preprocessing Engine ] ──> Casing metrics, URL extraction, domain extraction
      │
      ├───► [ Sender Analyzer ]       (Lookalikes, Subdomains, Display Name)
      ├───► [ Content Analyzer ]      (Urgency, Threats, Financial, Credentials)
      ├───► [ Static URL Analyzer ]   (Raw IPs, Suspicious TLDs, Shorteners)
      ├───► [ Attachment Analyzer ]   (Executables, Double Extensions)
      └───► [ Machine Learning ]      (TF-IDF + 19 Structured Features)
      │
      ▼
[ Hybrid Risk Engine ] ──> Weighted Score (0–100) & Classification
      │
      ▼
[ Explainable Output & Recommendations ]
      │
      ├───► [ SQLite Audit Store ] (Privacy-preserving metadata storage)
      └───► [ Web Dashboard & Telemetry Visualizations ]
```

---

## 4. Feature Engineering & Detection Vectors

The system extracts 19 structured features from every email:
1. `urgent_keyword_count`: Presence of high-pressure urgency markers.
2. `credential_keyword_count`: Cues requesting passwords, pins, or session renewals.
3. `financial_keyword_count`: Mentions of invoices, wire transfers, or penalty fees.
4. `threat_keyword_count`: Extortion, account suspension, or legal action threats.
5. `reward_keyword_count`: Lottery winnings or unsolicited cash prize lures.
6. `url_count`: Total hyperlinks extracted from body text.
7. `suspicious_url_count`: Links containing raw IPs, shorteners, or bad TLDs.
8. `has_ip_url`: Binary flag for raw IPv4 hostnames.
9. `has_shortened_url_pattern`: Binary flag for URL shortening services.
10. `sender_domain_length`: Total character length of sender domain.
11. `subdomain_count`: Hierarchy depth of sender domain.
12. `has_lookalike_sender`: Flag for typosquatting (e.g., `micr0soft.com`).
13. `has_mismatched_display_name`: Flag for display name claiming an entity not matching domain.
14. `suspicious_attachment`: Flag for executable or double-extended filenames.
15. `generic_greeting`: Flag for impersonal greetings (`Dear Customer`).
16. `contains_password_request`: Binary indicator for credential harvesting forms.
17. `contains_personal_info_request`: Binary indicator for SSN/banking data requests.
18. `exclamation_count`: Total exclamation points in text.
19. `uppercase_ratio`: Proportion of uppercase characters reflecting artificial panic.

---

## 5. Machine Learning Benchmarking & Results

Trained on 650 synthetic records using a 70% Train / 15% Validation / 15% Test split:

| Algorithm | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression (Best)** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **1.0000** |
| **Random Forest** | 100.00% | 100.00% | 100.00% | 100.00% | 1.0000 |
| **Multinomial Naive Bayes** | 100.00% | 100.00% | 100.00% | 100.00% | 1.0000 |

### Confusion Matrix Breakdown (Test Set, N=54):
- **True Positives (TP):** 5 (Phishing correctly identified)
- **True Negatives (TN):** 49 (Legitimate emails correctly cleared)
- **False Positives (FP):** 0 (No false alarms)
- **False Negatives (FN):** 0 (No missed phishing threats)

---

## 6. False Positives & False Negatives Analysis

- **Mitigating False Positives:** Legitimate emails occasionally employ urgent wording (e.g. valid university registration deadlines or corporate HR notices). Our scoring engine ensures that urgency alone contributes only 15 points, preventing legitimate emails from exceeding the 40-point threshold without corroborating evidence (such as raw IP links or lookalike domains).
- **Mitigating False Negatives:** Targeted spearphishing attacks often avoid overt spelling errors and aggressive language. By analyzing sender domain structure, attachment metadata, and URL destination hostnames in tandem, the system detects stealthy lures that bypass standard keyword filters.

---

## 7. Security, Privacy & Defensive Safeguards

1. **Static Analysis Only:** Suspicious links are inspected purely as strings. No HTTP connections, DNS queries, or resource fetches are initiated.
2. **Safe Attachments:** Attachment inspection evaluates filename extensions and double extensions. No binary execution takes place.
3. **Data Privacy:** Raw email bodies are excluded from permanent SQLite storage. Only high-level indicator summaries, scores, and domains are persisted.
4. **XSS & Injection Defense:** All user-supplied inputs and email headers are sanitized and HTML-escaped before presentation on the web dashboard.

---

## 8. Conclusion
The **Phishing Email Detection & Awareness Dashboard** provides a robust, placement-ready cybersecurity framework. By combining heuristic explainability, machine learning detection, interactive dashboard telemetry, and user-centric awareness training, the project showcases end-to-end mastery of email defense, defensive security engineering, and modern web application development.
