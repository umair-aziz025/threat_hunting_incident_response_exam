# Challenge 1 - Log Viewer Analysis

**Challenge Date**: November 9, 2025  
**Investigator**: Umair Aziz  
**Status**: ✅ COMPLETE (10/10 flags captured)

---

## 📁 Directory Structure

```
logviewer/
├── README.md                           # This file
├── challenge_file/                     # Original challenge files
├── logs/
│   └── all_logs_complete.json         # Complete dataset (500 events)
├── scripts/
│   ├── 01_extract_logs.py             # Log extraction from server
│   ├── 02_analyze_attacks.py          # Attack analysis script
│   └── 03_verify_answers.py           # Final verification script
└── reports/
    ├── FINAL_ANSWERS.md               # Complete answers with details
    ├── EXECUTIVE_SUMMARY.md           # Executive summary
    └── QUICK_REFERENCE.md             # Quick reference guide
```

---

## 🎯 Challenge Overview

This challenge involves analyzing security logs from the IR Training Log Server to identify a sophisticated multi-stage cyberattack that included:

- **Kerberos Ticket Forgery** (Golden & Silver Tickets)
- **Credential Theft** (LSASS Dump & Mimikatz)
- **Lateral Movement** (PsExec)
- **Malicious PowerShell Execution**

**Total Events Analyzed**: 500 security events  
**Time Period**: August 18, 2025 (01:15 - 08:19 UTC)  
**Attacker IP**: 10.10.5.23  
**Flags Captured**: 10/10 (100%)

---

## 🚀 Quick Start

### 1. Review the Answers
```bash
cat reports/FINAL_ANSWERS.md
```

### 2. Run Analysis Scripts
```bash
python scripts/02_analyze_attacks.py
python scripts/03_verify_answers.py
```

### 3. View Executive Summary
```bash
cat reports/EXECUTIVE_SUMMARY.md
```

---

## 📊 Key Findings Summary

| Attack Type | Time (UTC) | Host | MITRE ATT&CK |
|-------------|------------|------|--------------|
| Golden Ticket | 01:15 | DC01 | T1558.001 |
| Silver Ticket | 03:40 | WS02 | T1558.002 |
| LSASS Dump | 05:10 | WS01 | T1003.001 |
| PsExec Lateral Movement | 06:35 | FILE01 | T1570 |
| PowerShell Download Cradle | 07:00 | WS02 | T1059.001 |
| Mimikatz Execution | 07:40 | WS01 | T1003 |

---

## ✅ All Exam Questions Answered

- ✅ Q1: Golden Ticket Attack Detection
- ✅ Q2: Silver Ticket Identification
- ✅ Q3: LSASS Memory Dump
- ✅ Q4: PowerShell EncodedCommand
- ✅ Q5A: Mimikatz Execution
- ✅ Q5B: PsExec Lateral Movement
- ✅ Q5C: Timeline & Chronology

**Expected Score**: 90%+ (passing: 75%)

---

## 🔍 Methodology

1. **Data Collection**: Extracted 500 events from IR Log Server API
2. **Attack Identification**: Tagged 6 critical attack events
3. **Timeline Analysis**: Reconstructed 6-hour attack sequence
4. **MITRE Mapping**: Mapped all techniques to ATT&CK framework
5. **Verification**: Cross-referenced all findings

---

## 📝 Files Description

### Logs
- `all_logs_complete.json` - Complete JSON dataset with all 500 security events

### Scripts
- `01_extract_logs.py` - Extracts logs from http://127.0.0.1:8080/api/logs
- `02_analyze_attacks.py` - Identifies all attack events and generates findings
- `03_verify_answers.py` - Verifies all exam answers against log data

### Reports
- `FINAL_ANSWERS.md` - Detailed answers for all exam questions
- `EXECUTIVE_SUMMARY.md` - High-level executive summary
- `INVESTIGATION_REPORT.md` - Complete technical investigation report

---

## 🛠️ Tools & Technologies Used

- **Log Server**: IR Training Log Server (Port 8080)
- **Analysis**: Python 3.x with requests, json, datetime libraries
- **Format**: JSON logs, Markdown reports
- **Techniques**: Timeline analysis, MITRE ATT&CK mapping, correlation analysis

---

## 📖 Investigation Highlights

### Attack Vector
The attacker (IP: 10.10.5.23) gained initial access through Kerberos ticket forgery, established persistence through Golden and Silver tickets, harvested credentials via LSASS dump and Mimikatz, and performed lateral movement using PsExec.

### Critical Evidence
- Event ID 76: Golden Ticket with forged PAC signature
- Event ID 221: Silver Ticket with invalid PAC
- Event ID 311: LSASS dump with AccessMask 0x1FFFFF
- Event ID 396: PsExec lateral movement
- Event ID 421: Base64-encoded PowerShell download cradle
- Event ID 461: Mimikatz credential theft

### Time Gap Analysis
- Golden Ticket to PowerShell: **5h 45m**
- LSASS Dump occurred **before** PsExec by 1h 25m

---

## 🎓 Certification Preparation

This investigation demonstrates proficiency in:
- Log analysis and correlation
- Threat hunting methodologies
- MITRE ATT&CK framework application
- Timeline reconstruction
- Evidence documentation
- Incident response procedures

**CTHIRI Exam Readiness**: ✅ READY

---

## 📧 Contact

**Investigator**: Umair Aziz  
**Repository**: Deltaware_solution_internship_task  
**Date**: November 9, 2025

---

## 🔒 Classification

**Classification**: Training Exercise  
**Distribution**: Internal Use Only  
**Retention**: Keep for certification verification

---

*This investigation package is complete and ready for exam submission.*
