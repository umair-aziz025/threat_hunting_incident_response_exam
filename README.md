# Certified Threat Hunting and Incident Response I (CTHIRI)

## 🎓 Certification Status: ✅ PASSED

**Candidate:** Umair Aziz  
**Certification:** Certified Threat Hunting and Incident Response I (CTHIRI)  
**Date Completed:** November 9, 2025  
**Final Result:** PASSED ✅  

---

## 📊 Certification Overview

This repository contains the complete investigation work, scripts, and documentation from the CTHIRI certification exam. The certification validates practical skills in threat hunting, incident response, log analysis, and security operations.

### Certification Challenges Completed:

| Challenge | Status | Flags | Success Rate |
|-----------|--------|-------|--------------|
| **WEEK 6:** EDR Telemetry Validation | ✅ Complete | 20/20 | 100% |
| **WEEK 7:** IR Hunting Report Builder | ✅ Complete | 5/5 | 100% |
| **Quiz:** Security Knowledge Assessment | ✅ Complete | 11/11 | 100% |

**Overall Achievement:** 36/36 (100%)

---

## 🗂️ Repository Structure

```
CTHIRI_Investigation_Complete/
├── edrlog/                      # WEEK 6 - EDR Telemetry Validation
│   ├── challenge_file/          # Original challenge files
│   ├── logs/                    # EDR detection logs
│   ├── reports/                 # Investigation reports
│   ├── scripts/                 # Analysis scripts
│   └── README.md                # Challenge documentation
│
├── irhuntingreport/             # WEEK 7 - IR Hunting Report Builder
│   ├── challenge_file/          # Original challenge files
│   ├── logs/                    # Incident case logs
│   ├── reports/                 # Incident reports
│   ├── scripts/                 # Report generation scripts
│   └── README.md                # Challenge documentation
│
├── logviewer/                   # Log viewer utilities
├── networklog/                  # Network log analysis
├── quiz/                        # Security knowledge quiz
│   └── QUIZ_ANSWERS.md          # Quiz answers with explanations
│
└── README.md                    # This file
```

---

## 🎯 Skills Demonstrated

### Threat Hunting & Detection
- ✅ Hypothesis-driven threat hunting methodology
- ✅ Behavioral analytics and anomaly detection
- ✅ IOC extraction and analysis
- ✅ C2 beaconing pattern recognition
- ✅ JA3 TLS fingerprinting

### Incident Response
- ✅ Structured IR methodology (Containment → Eradication → Recovery)
- ✅ Malware behavior analysis
- ✅ Forensic investigation techniques
- ✅ Incident report writing
- ✅ Post-incident documentation

### Log Analysis
- ✅ ZEEK network telemetry analysis
- ✅ Sysmon process monitoring
- ✅ EDR behavioral analytics
- ✅ Proxy traffic inspection
- ✅ Windows Event Log analysis

### MITRE ATT&CK Framework
- ✅ Technique identification and mapping
- ✅ Tactic-based threat classification
- ✅ 17+ unique techniques across multiple attack vectors
- ✅ Adversary behavior understanding

### Technical Analysis
- ✅ DNS exfiltration detection (TXT records, base64 encoding)
- ✅ ICMP covert channel analysis
- ✅ HTTPS exfiltration identification
- ✅ HTTP/HTTPS C2 detection
- ✅ PowerShell obfuscation analysis
- ✅ Credential theft detection (LSASS dumps)

### Automation & Scripting
- ✅ Python scripting for security automation
- ✅ API interaction and data extraction
- ✅ JSON data manipulation
- ✅ Report generation automation

---

## 📈 Challenge Statistics

### WEEK 6: EDR Telemetry Validation
- **Total Detections:** 20
- **True Positives (BLOCK):** 10
- **False Positives (ALLOW):** 10
- **Accuracy:** 100%
- **Key Skills:** EDR analysis, context-based classification, severity assessment

### WEEK 7: IR Hunting Report Builder
- **Total Cases:** 5 complex incidents
- **Flags Captured:** 5/5 (100%)
- **MITRE Techniques Mapped:** 17
- **Attack Vectors Analyzed:**
  - DNS TXT exfiltration
  - ICMP payload exfiltration
  - HTTPS data theft
  - HTTP C2 beaconing
  - HTTPS encrypted C2

### Security Knowledge Quiz
- **Total Questions:** 11
- **Correct Answers:** 11/11 (100%)
- **Topics Covered:**
  - Threat hunting methodology
  - Log analysis and data sources
  - Windows internals (LSASS, Event IDs)
  - MITRE ATT&CK techniques
  - Incident response procedures

---

## 🔍 Notable Investigations

### Case Study 1: DNS Exfiltration via TXT Records
**Attack Vector:** PowerShell script exfiltrating data via DNS  
**Detection Method:** ZEEK DNS logs showing base64-encoded TXT queries  
**Key IOCs:** exfil.attacker.com, 200+ burst queries, 64KB data transfer  
**MITRE:** T1071.004 (DNS), T1132 (Encoding), T1041 (Exfiltration)

### Case Study 2: LSASS Memory Dump Detection
**Attack Vector:** Credential theft via LSASS process memory dump  
**Detection Method:** EDR telemetry showing process access patterns  
**Classification:** BLOCK (True Positive - Critical severity)  
**Impact:** Domain-wide credential compromise risk

### Case Study 3: HTTP C2 Beaconing
**Attack Vector:** Malware beaconing to external C2 server  
**Detection Method:** Periodic HTTP requests at 60-second intervals  
**Key IOCs:** 203.0.113.99, /beacon, /task endpoints  
**MITRE:** T1071.001 (Web Protocols), T1053 (Scheduled Task)

---

## 🛠️ Tools & Technologies

### Analysis Tools
- Python 3.x (requests, json, BeautifulSoup4)
- ZEEK network security monitor
- Sysmon (System Monitor)
- EDR platforms
- Proxy log analyzers

### Techniques Applied
- API reverse engineering
- JSON data parsing
- Log correlation analysis
- Pattern recognition
- Behavioral analytics
- MITRE ATT&CK mapping

---

## 📚 Key Learnings

### Detection Engineering
1. **Context is Critical:** Same tool (certutil, regsvr32) can be benign or malicious based on context
2. **Severity ≠ Maliciousness:** Critical severity doesn't always mean malicious
3. **Behavioral Patterns:** Periodicity, encoding, unusual protocols are strong indicators
4. **Parent-Child Relationships:** Process spawning patterns reveal attack chains

### Incident Response
1. **Structured Approach:** Hypothesis → Investigation → Detection → Response
2. **Containment First:** Isolate immediately to prevent lateral movement
3. **Keyword Validation:** IR reports need specific terminology (isolate, block, remove, etc.)
4. **Complete Documentation:** Containment, eradication, recovery must be thorough

### Threat Hunting
1. **Start with Hypothesis:** Don't hunt without a theory
2. **Use Multiple Data Sources:** Correlate logs from EDR, network, endpoint
3. **JA3 Fingerprinting:** Effective for detecting non-standard TLS clients
4. **Beaconing Detection:** Fixed intervals are a reliable C2 indicator

---

## 🏆 MITRE ATT&CK Coverage

### Tactics & Techniques Identified:

**Execution:**
- T1059.001 - PowerShell
- T1059.003 - Windows Command Shell

**Persistence:**
- T1053 - Scheduled Task/Job

**Defense Evasion:**
- T1027 - Obfuscated Files or Information
- T1140 - Deobfuscate/Decode Files or Information
- T1001 - Data Obfuscation

**Command and Control:**
- T1071.004 - Application Layer Protocol: DNS
- T1071.001 - Application Layer Protocol: Web Protocols
- T1095 - Non-Application Layer Protocol
- T1568 - Dynamic Resolution
- T1573 - Encrypted Channel

**Exfiltration:**
- T1041 - Exfiltration Over C2 Channel
- T1048 - Exfiltration Over Alternative Protocol
- T1132 - Data Encoding
- T1560 - Archive Collected Data
- T1005 - Data from Local System

**Total Unique Techniques:** 17

---

## 📖 Documentation

Each challenge directory contains:
- ✅ **README.md** - Challenge overview and methodology
- ✅ **INVESTIGATION_REPORT.md** - Detailed findings and analysis
- ✅ **FLAGS.md** - Captured flags with explanations
- ✅ **Scripts** - Analysis and automation tools
- ✅ **Logs** - Raw data and telemetry

---

## 🎓 Certification Value

### What This Certification Validates:
- Real-world incident response capabilities
- Hands-on threat hunting experience
- Log analysis across multiple data sources
- MITRE ATT&CK framework proficiency
- Security automation and scripting
- Technical report writing for stakeholders

### Career Applications:
- **SOC Analyst** - Detection and triage
- **Threat Hunter** - Proactive threat identification
- **Incident Responder** - Investigation and remediation
- **Security Engineer** - Detection rule development
- **DFIR Analyst** - Digital forensics and incident response

---

## 🚀 Future Applications

This certification provides foundational skills for:
- Advanced threat hunting programs
- SOC detection engineering
- Incident response team operations
- Threat intelligence analysis
- Red team/Blue team exercises
- Security architecture design

---

## 📞 Contact

**Candidate:** Umair Aziz  
**GitHub:** [@umair-aziz025](https://github.com/umair-aziz025)  
**Repository:** [threat_hunting_incident_response_exam](https://github.com/umair-aziz025/threat_hunting_incident_response_exam)

---

## ⚖️ Disclaimer

This repository contains educational materials from a cybersecurity certification exam. All challenges, scenarios, and techniques are used for legitimate security training purposes. The knowledge gained should only be applied for defensive security operations and authorized security testing.

---

## 🎉 Certification Achievement

**Status:** ✅ **PASSED**  
**Date:** November 9, 2025  
**Overall Score:** 100% (36/36 challenges completed successfully)  

*Certified Threat Hunting and Incident Response I (CTHIRI)*

---

**Last Updated:** November 9, 2025
