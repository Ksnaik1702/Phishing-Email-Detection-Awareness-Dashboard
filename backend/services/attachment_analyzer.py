"""
FILE NAME: attachment_analyzer.py
FILE PATH: backend/services/attachment_analyzer.py
PURPOSE: Safe static inspection of email attachment filenames and extensions.
         IMPORTANT DEFENSIVE SAFETY PROTOCOL:
         This module performs static string and metadata evaluation ONLY.
         It does NOT execute attachments or handle live malware binaries.
"""

from typing import List, Optional
from backend.models.schemas import AttachmentAnalysisResult, Finding
from backend.services.preprocessor import EmailPreprocessor

# Highly dangerous executable and script extensions
HIGH_RISK_EXECUTABLE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".pif",
    ".jar", ".msi", ".wsf", ".cpl", ".reg"
}

# Disk image and archive extensions often abused to bypass initial email scanners
ARCHIVE_CONTAINER_EXTS = {
    ".iso", ".img", ".vhd", ".cab", ".ace", ".arj", ".7z", ".rar"
}

# Macro-enabled office document extensions
MACRO_ENABLED_EXTS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

def analyze_attachment(filename: Optional[str]) -> Optional[AttachmentAnalysisResult]:
    """
    Performs static defensive risk analysis on an attachment filename.
    Returns AttachmentAnalysisResult or None if no attachment is attached.
    """
    if not filename or not filename.strip():
        return None
        
    findings: List[Finding] = []
    risk_score = 0.0
    fname = filename.strip()
    
    ext_meta = EmailPreprocessor.extract_attachment_extension(fname)
    ext = ext_meta["extension"]
    is_double = ext_meta["is_double"]
    
    is_executable = ext in HIGH_RISK_EXECUTABLE_EXTS
    is_archive = ext in ARCHIVE_CONTAINER_EXTS
    is_macro = ext in MACRO_ENABLED_EXTS
    
    # 1. High-Risk Executable or Script Check
    if is_executable:
        risk_score += 40.0
        findings.append(Finding(
            indicator_type="ATTACHMENT",
            description=f"Directly executable/script file extension '{ext}'. Legitimate organizations rarely email executable files.",
            severity="CRITICAL",
            weight=40.0
        ))
        
    # 2. Deceptive Double Extension Check (e.g. invoice.pdf.exe)
    if is_double:
        risk_score += 35.0
        parts_str = "".join(ext_meta["parts"])
        findings.append(Finding(
            indicator_type="ATTACHMENT",
            description=f"Double extension detected ('{parts_str}'). Attackers use this to disguise executables as benign documents.",
            severity="CRITICAL",
            weight=35.0
        ))
        
    # 3. Macro-Enabled Document Check
    if is_macro:
        risk_score += 25.0
        findings.append(Finding(
            indicator_type="ATTACHMENT",
            description=f"Macro-enabled document format '{ext}' capable of executing embedded Visual Basic scripts.",
            severity="HIGH",
            weight=25.0
        ))
        
    # 4. Container / Disk Image Format Check
    if is_archive:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="ATTACHMENT",
            description=f"Container/Archive extension '{ext}'. Containers can hide payloads and circumvent standard inspection.",
            severity="MEDIUM",
            weight=15.0
        ))
        
    is_suspicious = (risk_score > 0.0)
    
    if not is_suspicious:
        findings.append(Finding(
            indicator_type="ATTACHMENT",
            description=f"Attachment format '{ext}' is standard document format, but caution is always advised for unexpected attachments.",
            severity="INFO",
            weight=0.0
        ))
        
    capped_score = min(100.0, max(0.0, risk_score))
    
    return AttachmentAnalysisResult(
        filename=fname,
        extension=ext,
        is_suspicious=is_suspicious,
        is_executable_or_script=is_executable,
        is_double_extension=is_double,
        risk_score=capped_score,
        findings=findings
    )
