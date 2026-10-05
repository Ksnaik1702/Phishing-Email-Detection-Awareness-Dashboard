"""
FILE NAME: generate_dataset.py
FILE PATH: data/generate_dataset.py
PURPOSE: Generates a high-quality, 600+ record safe synthetic dataset for email phishing detection and awareness.
         Uses Python's built-in csv module (with pandas fallback) so it can run immediately without dependencies.
         All domains and IPs use RFC 2606 and RFC 5737 safe/reserved test values.
"""

import os
import random
import csv

SAFE_LEGIT_DOMAINS = [
    "example.com", "example.org", "example.net", "university.example.edu",
    "corp.example.com", "health.example.org", "store.example.net", "tech.example.org"
]

SYNTHETIC_PHISH_DOMAINS = [
    "account-verify.invalid.test", "security-update.invalid.test",
    "banking-secure-portal.invalid.test", "login-microsoft-auth.invalid.test",
    "payroll-portal-urgent.invalid.test", "invoice-settlement.invalid.test",
    "parcel-tracking-update.invalid.test", "executive-wire-transfer.invalid.test",
    "prize-claim-center.invalid.test", "helpdesk-password-reset.invalid.test"
]

SAFE_TEST_IPS = [
    "192.0.2.14", "198.51.100.45", "203.0.113.88", "198.51.100.10", "192.0.2.99"
]

LEGIT_TEMPLATES = [
    {
        "sender": "registrar@university.example.edu",
        "domain": "university.example.edu",
        "subject": "Semester Course Registration Window Open",
        "body": "Dear Student,\n\nThe course registration window for the upcoming spring semester is now open. Please review your degree audit and select your courses through the standard campus portal.\n\nAcademic Advising Office",
        "urls": "https://university.example.edu/portal/courses",
        "attachment": "course_catalog.pdf"
    },
    {
        "sender": "hr-benefits@corp.example.com",
        "domain": "corp.example.com",
        "subject": "Annual Open Enrollment Benefits Information",
        "body": "Hello Team,\n\nOur open enrollment period begins next Monday. Please review the attached summary of medical, dental, and retirement plan options for the next fiscal year.\n\nBest regards,\nHuman Resources Department",
        "urls": "https://corp.example.com/intranet/benefits",
        "attachment": "benefits_summary_2026.pdf"
    },
    {
        "sender": "pm-lead@tech.example.org",
        "domain": "tech.example.org",
        "subject": "Sprint Review and Retrospective Notes",
        "body": "Hi everyone,\n\nThanks for attending our bi-weekly sprint review. The sprint deliverables have been deployed to the staging environment for QA testing. Feel free to review the ticket tracker.\n\nRegards,\nProject Management",
        "urls": "https://tech.example.org/jira/sprint-42",
        "attachment": ""
    },
    {
        "sender": "calendar-service@corp.example.com",
        "domain": "corp.example.com",
        "subject": "Meeting Reminder: Defensive Security Working Group",
        "body": "Reminder: Defensive Security Working Group is scheduled for tomorrow at 10:00 AM UTC in Conference Room B and via video link.\n\nAgenda: Threat modeling and logging policy review.",
        "urls": "https://corp.example.com/calendar/event-8821",
        "attachment": ""
    },
    {
        "sender": "orders@store.example.net",
        "domain": "store.example.net",
        "subject": "Order Confirmation #EX-904128",
        "body": "Thank you for your order! We have received your order #EX-904128 and are preparing it for shipment. You can track your package status in your account dashboard.\n\nCustomer Support Team",
        "urls": "https://store.example.net/orders/EX-904128",
        "attachment": "order_receipt.pdf"
    },
    {
        "sender": "newsletter@health.example.org",
        "domain": "health.example.org",
        "subject": "Monthly Wellness & Health Digest - Issue #14",
        "body": "Welcome to this month's wellness newsletter. Discover healthy ergonomics tips for desk workers, seasonal nutrition advice, and mindfulness exercises.\n\nHealth & Wellness Community",
        "urls": "https://health.example.org/newsletter/edition-14",
        "attachment": ""
    },
    {
        "sender": "security-notification@example.com",
        "domain": "example.com",
        "subject": "Security Notice: Password Successfully Updated",
        "body": "Hello,\n\nThis is an automated confirmation that your account password was changed on Monday at 09:14 UTC. If you initiated this change, no further action is required.\n\nAccount Security Team",
        "urls": "https://example.com/account/security-log",
        "attachment": ""
    },
    {
        "sender": "notifications@bank.example.org",
        "domain": "bank.example.org",
        "subject": "Your Monthly Statement Is Ready for Viewing",
        "body": "Dear Customer,\n\nYour latest electronic account statement is ready for viewing in our online banking portal. Log in to your account at your convenience to view or download it.\n\nCustomer Care Center",
        "urls": "https://bank.example.org/online/statements",
        "attachment": "statement_info.pdf"
    }
]

PHISH_TEMPLATES = [
    {
        "sender_prefix": "support-alert",
        "subject": "URGENT: Immediate Account Suspension Notice - Action Required",
        "body": "Dear Customer,\n\nYour account has been flagged for immediate suspension due to suspicious login activity. You must verify your password and personal credentials within 24 hours or your access will be permanently terminated.\n\nClick here immediately to restore access.",
        "url_template": "http://{ip}/verify-account-portal/login.php",
        "attachment": ""
    },
    {
        "sender_prefix": "billing-dept",
        "subject": "Overdue Invoice #INV-990184 - Final Notice Before Legal Action",
        "body": "Attention Accounts Payable,\n\nPlease find attached the outstanding invoice payment. Failure to settle this invoice immediately will result in financial penalties and collections escalation. Open the attached invoice to verify details.",
        "url_template": "http://{domain}/download/invoice_doc?id=990184",
        "attachment": "overdue_invoice_march.pdf.exe"
    },
    {
        "sender_prefix": "reward-claims",
        "subject": "CONGRATULATIONS: You Have Won $10,000 Cash Prize!",
        "body": "Dear Winner,\n\nYou have been selected as the grand winner of the annual cash lottery draw. To claim your reward, confirm your full name, bank details, and social security number immediately before the claim expires!",
        "url_template": "http://{domain}/claim-prize-center/winner-verify",
        "attachment": "lottery_claim_form.vbs"
    },
    {
        "sender_prefix": "admin-helpdesk",
        "subject": "Critical: Password Expiry Notification - Keep Same Password Now",
        "body": "Dear User,\n\nYour system password expires today at 5:00 PM. To prevent service disruption and keep your current password, click the verification link below and submit your current login credentials.",
        "url_template": "http://{ip}/auth/password-renew-session",
        "attachment": ""
    },
    {
        "sender_prefix": "package-delivery",
        "subject": "Delivery Failed: Package Address Incomplete - Confirm Immediately",
        "body": "Your package could not be delivered due to an incorrect shipping address. A holding fee of $2.50 is required to reschedule delivery. Click below to verify your card details and address.",
        "url_template": "http://{domain}/delivery/track-package?user=ref84",
        "attachment": "shipment_label_doc.scr"
    },
    {
        "sender_prefix": "payroll-update",
        "subject": "URGENT: Employee Direct Deposit Information Verification",
        "body": "All employees are required to verify their payroll direct deposit information immediately to prevent delays in this month's salary disbursement. Click the link to update your bank credentials.",
        "url_template": "http://{domain}/hr/payroll-verification",
        "attachment": ""
    },
    {
        "sender_prefix": "ceo-office",
        "subject": "CONFIDENTIAL: Urgent Wire Transfer Request from CEO",
        "body": "Are you currently at your desk? I need an urgent international wire transfer processed immediately for a confidential vendor acquisition. Do not discuss this with anyone; click below for bank instructions.",
        "url_template": "http://{ip}/executive/wire-instructions",
        "attachment": "wire_transfer_mandate.bat"
    }
]

def generate_synthetic_dataset(num_records=650, output_path="data/phishing_email_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    records = []
    
    num_legit = num_records // 2
    num_phish = num_records - num_legit
    
    # 1. Generate Legitimate Samples
    for i in range(1, num_legit + 1):
        tmpl = random.choice(LEGIT_TEMPLATES)
        email_id = f"LEGIT_{i:04d}"
        
        subjects = [
            tmpl["subject"],
            f"[Internal] {tmpl['subject']}",
            f"Update: {tmpl['subject']}",
            f"Notice - {tmpl['subject']}"
        ]
        chosen_subject = random.choice(subjects)
        
        sender = tmpl["sender"]
        domain = tmpl["domain"]
        body = tmpl["body"] + f"\n\nRef: SYS-REF-{random.randint(1000, 9999)}"
        urls = tmpl["urls"] if random.random() > 0.15 else ""
        attachment = tmpl["attachment"] if random.random() > 0.3 else ""
        
        records.append({
            "email_id": email_id,
            "sender": sender,
            "sender_domain": domain,
            "subject": chosen_subject,
            "body": body,
            "urls": urls,
            "attachment_name": attachment,
            "label": "LEGITIMATE"
        })
        
    # 2. Generate Phishing Samples
    for i in range(1, num_phish + 1):
        tmpl = random.choice(PHISH_TEMPLATES)
        email_id = f"PHISH_{i:04d}"
        
        domain = random.choice(SYNTHETIC_PHISH_DOMAINS)
        sender = f"{tmpl['sender_prefix']}@{domain}"
        
        urgency_prefixes = ["URGENT: ", "FINAL NOTICE: ", "ACTION REQUIRED: ", "SECURITY ALERT: ", "WARNING: "]
        chosen_subject = random.choice(urgency_prefixes) + tmpl["subject"]
        
        if "{ip}" in tmpl["url_template"]:
            ip = random.choice(SAFE_TEST_IPS)
            url = tmpl["url_template"].format(ip=ip)
        else:
            url = tmpl["url_template"].format(domain=domain)
            
        if random.random() > 0.6:
            extra_url = f"http://{random.choice(SAFE_TEST_IPS)}/login-confirm"
            url = f"{url} {extra_url}"
            
        attachment = tmpl["attachment"] if random.random() > 0.4 else ""
        
        records.append({
            "email_id": email_id,
            "sender": sender,
            "sender_domain": domain,
            "subject": chosen_subject,
            "body": tmpl["body"],
            "urls": url,
            "attachment_name": attachment,
            "label": "PHISHING"
        })
        
    random.shuffle(records)
    
    fieldnames = ["email_id", "sender", "sender_domain", "subject", "body", "urls", "attachment_name", "label"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
        
    legit_cnt = sum(1 for r in records if r["label"] == "LEGITIMATE")
    phish_cnt = sum(1 for r in records if r["label"] == "PHISHING")
    print(f"[+] Successfully generated {len(records)} synthetic email records at: {output_path}")
    print(f"    - Legitimate records: {legit_cnt}")
    print(f"    - Phishing records:   {phish_cnt}")
    return records

if __name__ == "__main__":
    generate_synthetic_dataset()
