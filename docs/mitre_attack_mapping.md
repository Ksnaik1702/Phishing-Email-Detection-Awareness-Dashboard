# MITRE ATT&CK Framework Mapping for Email Security

This document establishes the formal defensive mapping between the indicators detected by the **Phishing Email Detection & Awareness Dashboard** and the **MITRE ATT&CK Enterprise Framework**.

---

## Matrix Summary

| MITRE Technique ID | Technique Name | Sub-Technique / Vector | Project Detection Logic | Defensive Countermeasures |
| :--- | :--- | :--- | :--- | :--- |
| **T1566** | Phishing | General Social Engineering | Content Urgency & Fear Pattern Analysis | User Security Awareness Training |
| **T1566.001** | Spearphishing Attachment | Malicious File Attachments | Static Filename & Double Extension Inspection (`.pdf.exe`, `.scr`, `.bat`) | Attachment Sandboxing & Extension Blocking |
| **T1566.002** | Spearphishing Link | Deceptive / Malicious Hyperlinks | Static URL String Analyzer (Raw IPs, Shorteners, Obfuscated Hostnames) | Web Proxy Blocking, Safe DNS, Link Rewriting |
| **T1566.003** | Spearphishing via Service | Impersonation via Legitimate Clouds | Lookalike Domain & Display-Name Mismatch Engine | Multi-Factor Authentication (MFA), DMARC/DKIM/SPF |
| **T1204.001** | User Execution: Malicious Link | End-User Clicking Phishing Link | "Before You Click" Interactive Hygiene Checklist | Endpoint Protection & Out-of-Band Verification |
| **T1204.002** | User Execution: Malicious File | End-User Launching Executable Attachment | Attachment Risk Warning & Non-Execution Protocols | AppLocker / Software Restriction Policies |
| **T1078** | Valid Accounts | Credential Harvesting via Lure Pages | Credential Harvesting Keyword & Form Detection | Conditional Access & FIDO2 / Passkeys |

---

## Detailed Technique Breakdown

### 1. T1566.001: Spearphishing Attachment
- **Adversary Behavior**: Threat actors deliver an email with a weaponized attachment (e.g., invoice masquerading as a PDF but having an executable extension like `.exe`, `.scr`, or `.vbs`).
- **Detection in Project**: `backend/services/attachment_analyzer.py` inspects filename structure, detects double extensions (`invoice.pdf.exe`), and flags script/executable extensions without executing the file.

### 2. T1566.002: Spearphishing Link
- **Adversary Behavior**: Emails contain hyperlinks directing targets to credential harvesting portals or exploit delivery infrastructure. Adversaries frequently use raw IP addresses or URL shorteners to evade domain-based reputation filters.
- **Detection in Project**: `backend/services/url_analyzer.py` statically identifies raw IPv4 hostnames (`http://198.51.100.10`), URL shortener services (`bit.ly`), unencrypted HTTP schemes, and login/auth keywords embedded in URL paths.

### 3. T1566.003: Spearphishing via Service / Impersonation
- **Adversary Behavior**: Adversaries register lookalike domains using character swaps (e.g., `micr0soft.com` or `paypa1.com`) or craft display names that do not match the originating sending domain.
- **Detection in Project**: `backend/services/sender_analyzer.py` compares the display name against the envelope sender and executes regex scans for known typosquatting patterns.
