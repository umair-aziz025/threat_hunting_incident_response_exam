# WEEK 7 - IR Hunting Report Builder - Summary

## 🎯 Challenge Complete!

**Challenge:** IR Hunting Report Builder  
**Status:** ✅ **COMPLETED**  
**Flags Captured:** 5/5 (100%)  
**Date:** November 9, 2025  

---

## 📊 Results

### All Flags Captured ✅

| Case | Code | Flag | Status |
|------|------|------|--------|
| **Case 1** | SCN_DNS_EXFIL | `RTL{b88ed147877c1c3769a4fb4823344395}` | ✅ |
| **Case 2** | SCN_ICMP_EXFIL | `RTL{693884d6ed8bdbc22dd24f594da8fb98}` | ✅ |
| **Case 3** | SCN_HTTPS_EXFIL | `RTL{b06aed4fbb6c0c8d3cd8a2d6749e2b99}` | ✅ |
| **Case 4** | SCN_C2_HTTP | `RTL{e62aa614709b00098ccee79c967870ef}` | ✅ |
| **Case 5** | SCN_C2_HTTPS | `RTL{193577d2e225015c07fba994502860df}` | ✅ |

---

## 🔍 Incident Cases Overview

### Case 1: DNS Exfiltration via TXT Records
- **Attack:** PowerShell script exfiltrating data via base64-encoded DNS TXT queries
- **Target:** exfil.attacker.com
- **Victim:** User jdoe on ENG-03
- **Volume:** 200+ DNS queries, ~64KB data
- **MITRE:** T1071.004, T1132, T1041, T1027, T1568, T1005

### Case 2: ICMP Exfiltration
- **Attack:** Large ICMP echo payloads for data exfiltration
- **Target:** 203.0.113.45
- **Victim:** User msmith on WS-07
- **Method:** `ping -n 60 -l 1400` (1400-byte payloads)
- **MITRE:** T1048, T1095, T1041, T1027

### Case 3: HTTPS Exfiltration
- **Attack:** Python script uploading financial data to external endpoint
- **Target:** cdn-drop.example (198.51.100.120)
- **Victim:** User analyst on FIN-11
- **Data:** Q3.zip financial ledger (12.8MB)
- **MITRE:** T1041, T1071.001, T1560, T1027

### Case 4: HTTP Command & Control
- **Attack:** Beaconing malware with command tasking
- **Target:** C2 server 203.0.113.99
- **Victim:** User jdoe on WS-19
- **Pattern:** 60-second beacons, command execution via /task
- **Persistence:** Scheduled task
- **MITRE:** T1071.001, T1059.003, T1053, T1105

### Case 5: HTTPS Command & Control (Encrypted)
- **Attack:** TLS-encrypted C2 with PowerShell encoded commands
- **Target:** cdn-c2.example (198.51.100.200)
- **Victim:** User dev.build on LAP-DEV01
- **Signature:** JA3 fingerprint 769,4865,4867
- **Commands:** PowerShell -enc (base64 encoded)
- **MITRE:** T1071.001, T1059.001, T1573, T1140, T1001

---

## 🛠️ Tools & Scripts Created

1. **01_explore_ir_api.py** - API endpoint discovery
2. **02_analyze_html.py** - HTML/JavaScript analysis to find data endpoint
3. **03_extract_scenarios.py** - Extract all 5 incident cases from API
4. **04_analyze_cases.py** - Parse and display case details
5. **05_generate_reports.py** - Generate and submit incident reports

---

## 📁 Files Generated

- `ir_scenarios.json` - Complete incident case data (5 cases, 219 lines)
- `ir_flags.json` - Captured flags
- `ir_report_page.html` - Reference HTML interface
- `README.md` - Challenge overview and methodology
- `INVESTIGATION_REPORT.md` - Detailed investigation findings
- `FLAGS.md` - Flag capture documentation
- `SUMMARY.md` - This summary document

---

## 🎓 Skills Demonstrated

### Incident Response
✅ Log analysis (ZEEK, Sysmon, EDR, Proxy)  
✅ Threat identification and classification  
✅ MITRE ATT&CK framework mapping  
✅ IOC extraction and analysis  
✅ Incident report writing  
✅ Containment, eradication, recovery planning  

### Technical Skills
✅ API reverse engineering  
✅ Python scripting and automation  
✅ JSON data manipulation  
✅ Web application analysis  
✅ Network protocol analysis (DNS, ICMP, HTTP, HTTPS)  
✅ Malware behavior analysis  

### Security Concepts
✅ DNS exfiltration techniques  
✅ Alternative protocol abuse (ICMP)  
✅ Command & Control (C2) operations  
✅ TLS fingerprinting (JA3)  
✅ PowerShell obfuscation  
✅ Persistence mechanisms  

---

## 📈 MITRE ATT&CK Coverage

### Tactics & Techniques Used:

**Execution:**
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- T1059.001 - Command and Scripting Interpreter: PowerShell

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

**Other:**
- T1105 - Ingress Tool Transfer

**Total Techniques Covered:** 17 unique MITRE ATT&CK techniques

---

## 🏆 Achievement Summary

✅ **API Discovery** - Successfully found hidden `/api/scenarios` endpoint  
✅ **Data Extraction** - Retrieved complete incident data (5 cases, 219 lines JSON)  
✅ **Log Analysis** - Parsed logs from 4 different sources (ZEEK, Sysmon, EDR, Proxy)  
✅ **MITRE Mapping** - Correctly identified 17 ATT&CK techniques across 5 cases  
✅ **Report Generation** - Created comprehensive incident reports with all required fields  
✅ **Validation Success** - All reports passed keyword validation on second attempt  
✅ **100% Completion** - Captured all 5 flags successfully  

---

## 🔐 Security Insights

### Key Findings:

1. **DNS as Exfil Channel:** DNS TXT records can bypass traditional DLP, requires specialized monitoring
2. **ICMP Abuse:** Large ICMP payloads indicate potential data exfiltration
3. **HTTPS Blind Spot:** Encrypted traffic requires TLS inspection and behavioral analysis
4. **C2 Patterns:** Periodic beaconing with fixed intervals is a strong IOC
5. **PowerShell Risk:** Encoded commands and hidden execution flags are major red flags
6. **JA3 Value:** TLS fingerprinting can identify non-standard clients and malware

### Detection Opportunities:

- **Network:** DNS query logging, ICMP payload monitoring, HTTP beaconing detection, JA3 analysis
- **Endpoint:** PowerShell script block logging, suspicious process relationships, scheduled task monitoring
- **Behavioral:** Periodic network patterns, bulk data access, encoding/encryption usage

---

## 📖 Lessons Learned

1. **API Exploration:** Don't assume API structure - analyze client-side code to find real endpoints
2. **Keyword Validation:** IR reports require specific terminology for validation (isolate, block, remove, etc.)
3. **MITRE Importance:** Proper technique mapping demonstrates understanding of adversary behavior
4. **IOC Context:** IOCs are most valuable when correlated with behavioral patterns
5. **Report Structure:** Incident reports need standardized fields: containment, eradication, recovery

---

## 🎉 Challenge Status

**FINAL SCORE: 5/5 FLAGS (100%)**

All incident response cases successfully analyzed, documented, and reported.  
All flags captured and verified.  
Investigation directory created with comprehensive documentation.

**Challenge:** ✅ **COMPLETE**  
**Analyst:** Umair Aziz  
**Date:** November 9, 2025  
**Time Invested:** ~2 hours

---

## 📚 Documentation Structure

```
WEEK 7 - IR Hunting Report/
├── README.md                    # Challenge overview & methodology
├── INVESTIGATION_REPORT.md      # Detailed findings & analysis
├── FLAGS.md                     # Flag capture documentation
├── SUMMARY.md                   # This summary document
├── ir_scenarios.json            # Complete incident case data
├── ir_flags.json                # Captured flags
├── ir_report_page.html          # HTML interface reference
├── 01_explore_ir_api.py         # API discovery script
├── 02_analyze_html.py           # HTML analysis script
├── 03_extract_scenarios.py      # Data extraction script
├── 04_analyze_cases.py          # Case analysis script
└── 05_generate_reports.py       # Report generation & submission
```

**Total Files:** 14 files  
**Documentation:** 4 markdown files  
**Scripts:** 5 Python files  
**Data:** 3 JSON files  
**Reference:** 1 HTML file  

---

## ✨ Next Steps

With WEEK 7 complete, you now have:
- ✅ Complete investigation directory
- ✅ All scripts and data files
- ✅ Comprehensive documentation
- ✅ All 5 flags captured and verified

**Ready for next challenge whenever you are!** 🚀
