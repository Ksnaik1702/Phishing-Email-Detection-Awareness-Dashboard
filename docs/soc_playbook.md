# SOC Analyst Incident Response Playbook: Email Phishing Triage

This standard operating procedure (SOP) guides Security Operations Center (SOC) Level-1 and Level-2 analysts in handling reported suspicious emails using the **PhishGuard Defensive Dashboard**.

---

## 1. Incident Triage Workflow

```
[ Email Reported by User ]
            |
            v
[ Phase 1: Ingestion & Input ]
  • Ingest sender, subject, body, URLs, and attachment into PhishGuard
            |
            v
[ Phase 2: Automated Multi-Vector Analysis ]
  • Sender: Check display name mismatch, typosquatting, domain age
  • Content: Check urgency, threats, financial requests, credential lures
  • URLs: Static inspection for raw IPs, unencrypted HTTP, shorteners
  • Attachment: Extension and double-extension analysis
            |
            v
[ Phase 3: Score & Classification Review ]
  • SAFE (0-10)       -> Inform user, close ticket as benign
  • LOW RISK (11-40)  -> Quick validation, close with educational tip
  • SUSPICIOUS (41-70)-> In-depth analyst review of destination URLs
  • HIGH RISK (71-100)-> Execute containment & remediation protocols
            |
            v
[ Phase 4: Incident Containment & Eradication ]
  1. Purge matching email from all mailboxes across organization
  2. Block sender domain and sending IP at the Secure Email Gateway (SEG)
  3. Add malicious URLs/IPs to perimeter Firewall / Web Proxy blocklists
  4. Force password reset & revoke active sessions if user clicked or entered credentials
            |
            v
[ Phase 5: Post-Incident Activity ]
  • Log IoCs in Threat Intelligence Platform (TIP)
  • Assign micro-lesson module to affected users in Security Awareness Portal
```

---

## 2. Key Analyst Responsibilities by Role

### SOC Analyst (Tier 1 / Tier 2)
- Performs initial triage on reported emails using automated risk scoring.
- Validates whether an alert is a True Positive or False Positive.
- Initiates mailbox search-and-purge operations for confirmed phishing campaigns.

### Email Security Analyst
- Tunes Secure Email Gateway (SEG) policies, spam filters, and rule thresholds.
- Monitors SPF, DKIM, and DMARC alignment and evaluates sender domain reputation.
- Hardens email routing rules against display-name spoofing and lookalike domains.

### Threat Intelligence Analyst
- Extracts Indicators of Compromise (IoCs): sender domains, lure URLs, attachment hashes.
- Correlates campaigns with known Advanced Persistent Threat (APT) groups or cybercrime rings.
- Disseminates defensive blocklists to Firewall and Endpoint Detection and Response (EDR) teams.

### Security Awareness Specialist
- Reviews common failure modes in user reporting.
- Designs targeted, positive micro-lessons addressing recent lure trends (e.g. fake invoices, HR open enrollment).
- Measures reduction in phishing click-through rates over time.
