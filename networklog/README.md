# Challenge 2 - Network Log Investigation
## Data Exfiltration & C2 Detection Analysis

**Challenge Date**: November 9, 2025  
**Status**: ✅ COMPLETE (10/10 flags captured)

---

## 📁 Directory Structure

```
networklog/
│
├── README.md                          # This file
├── challenge_file/                    # Original challenge files
│
├── scripts/                           # Analysis Scripts
│   ├── 01_extract_network_logs.py    - Extract all 927 logs from IR server
│   ├── 02_analyze_exfiltration_c2.py - Comprehensive analysis of exfil & C2
│   ├── 03_extract_answers.py         - Extract specific answers to questions
│   └── 04_verify_answers.py          - Verify all answers against log data
│
├── logs/                              # Network Traffic Data
│   ├── all_network_logs.json         - Complete dataset (927 network logs)
│   └── answers.json                  - All exam answers in JSON format
│
└── reports/                           # Investigation Reports
    ├── FINAL_ANSWERS.md              - Complete answers with evidence
    ├── EXECUTIVE_SUMMARY.md          - High-level findings summary
    ├── QUICK_REFERENCE.md            - Quick answer lookup sheet
    └── INVESTIGATION_COMPLETE.md     - Complete investigation details
```

---

## 🎯 Challenge Overview

This challenge focuses on analyzing network traffic logs to identify data exfiltration and command & control (C2) activities. The investigation covers:

- **Data Exfiltration Detection**
- **C2 Communication Analysis**
- **Protocol Analysis (DNS, HTTP, HTTPS)**
- **IOC Extraction**

**Total Logs Analyzed**: 927 network events  
**Flags Captured**: 10/10 (100%)
   python scripts/03_extract_answers.py
   ```

4. **Verify All Answers**:
   ```bash
   python scripts/04_verify_answers.py
   ```

---

## 📊 Investigation Summary

### Total Network Logs Analyzed: **927**

**Protocol Distribution:**
- TCP: 570 logs
- UDP: 240 logs  
- ICMP: 117 logs

**Application Distribution:**
- OTHER: 224 logs
- HTTPS: 134 logs
- NTP: 132 logs
- HTTP: 121 logs
- ICMP: 117 logs
- DNS: 108 logs
- SMB: 91 logs

---

## 🎯 Key Findings

### 1. DNS Exfiltration
- **Source Host:** 10.0.5.50
- **Base Domain:** exfil.attacker.net
- **Query Types:** A, TXT
- **Resolver IP:** 10.0.0.53
- **Total Queries:** 6
- **Time Range:** 01:00:25Z - 01:02:05Z

**Evidence:** Encoded data in subdomains like:
- `k28i23ew.4f2f7061727436.data.exfil.attacker.net`
- `46vt67b3.4e2f7061727435.data.exfil.attacker.net`

---

### 2. ICMP Exfiltration
- **Source IP:** 10.0.5.51
- **Destination IP:** 198.51.100.10
- **Type:** echo-request
- **Encoding:** Base64
- **Total Packets:** 8 suspicious packets
- **Average Size:** 682 bytes (normal ping: 64-98 bytes)
- **Time Range:** 02:20:00Z - 02:22:06Z

**Evidence:** Base64-encoded payloads in ICMP echo requests
- Example: `Qm2gYmdUrsktJHSl7PeMxPf+O0o707yzC9FO/mfSInS5gXkkffESZ...`

---

### 3. HTTPS Exfiltration
- **Host:** secure-updates.cdn-cloudsync.net
- **Method:** POST
- **URI:** /sync/upload
- **Single Transfer Size:** 150,000 bytes
- **Total Exfiltration:** 750,000 bytes (5 requests)
- **Source Host:** 10.0.5.60
- **Destination:** 203.0.113.200
- **Timestamp:** 2025-08-18T03:47:40Z (largest transfer)

**Evidence:** Disguised as legitimate CDN update traffic

---

### 4. HTTP Command & Control (C2)
- **C2 Server:** update-service.net
- **Destination IP:** 203.0.113.55
- **Compromised Host:** 10.0.5.40
- **User-Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.3
- **Total Requests:** 5

**C2 Endpoints:**
- `/api/beacon` - Beaconing
- `/api/task` - Task retrieval
- `/api/result` - Result submission

**Command Execution:**
- **Time:** 2025-08-18T04:30:10Z
- **Command:** `cmd:whoami` (Base64 decoded from: Y21kOndob2FtaQ==)
- **Method:** GET to /api/task

---

### 5. HTTPS Command & Control (C2)
- **C2 Server:** cdn-cloudupdates.net
- **Destination IP:** 198.51.100.23
- **Compromised Host:** 10.0.5.30
- **Total Requests:** 3

**C2 Endpoints:**
- `/v1/checkin` - Check-in
- `/v1/tasks` - Task retrieval
- `/v1/results` - Result submission

**Evidence:** Disguised as legitimate CDN traffic

---

## 🔴 Indicators of Compromise (IOCs)

### Malicious Domains
```
exfil.attacker.net
update-service.net
cdn-cloudupdates.net
secure-updates.cdn-cloudsync.net
```

### Malicious External IPs
```
203.0.113.55      - HTTP C2 server
203.0.113.200     - HTTPS exfiltration server
198.51.100.23     - HTTPS C2 server
198.51.100.10     - ICMP exfiltration destination
```

### Compromised Internal Hosts
```
10.0.5.50  - DNS exfiltration
10.0.5.51  - ICMP exfiltration
10.0.5.60  - HTTPS exfiltration
10.0.5.40  - HTTP C2 communication
10.0.5.30  - HTTPS C2 communication
```

---

## 📈 Attack Timeline

```
2025-08-18T01:00:25Z  - DNS exfiltration begins (10.0.5.50)
2025-08-18T01:02:05Z  - DNS exfiltration ends (6 queries total)

2025-08-18T02:20:00Z  - ICMP exfiltration begins (10.0.5.51)
2025-08-18T02:22:06Z  - ICMP exfiltration ends (8 packets)

2025-08-18T03:47:40Z  - Largest HTTPS exfiltration (150KB, 10.0.5.60)

2025-08-18T04:30:10Z  - HTTP C2 command execution: cmd:whoami (10.0.5.40)
```

**Total Attack Duration:** Approximately 3.5 hours

---

## ✅ Verification Results

All answers have been verified against the source logs:

- **Total Checks:** 22
- **Passed:** 22
- **Failed:** 0
- **Success Rate:** 100%

### Verified Components:
✓ DNS Exfiltration (4 checks)  
✓ ICMP Exfiltration (5 checks)  
✓ HTTPS Exfiltration (4 checks)  
✓ HTTP C2 (5 checks)  
✓ HTTPS C2 (4 checks)

---

## 🛡️ Recommendations

### Immediate Actions:
1. **Isolate compromised hosts** (10.0.5.30, 10.0.5.40, 10.0.5.50, 10.0.5.51, 10.0.5.60)
2. **Block malicious IPs** at firewall level
3. **Block malicious domains** at DNS level
4. **Rotate credentials** for all affected systems
5. **Review user accounts** on compromised hosts for persistence

### Long-term Improvements:
1. **Implement DNS monitoring** for unusual query patterns and TXT records
2. **Monitor ICMP traffic** for large packet sizes and unusual payloads
3. **Implement SSL/TLS inspection** for HTTPS traffic
4. **Deploy EDR solutions** on all endpoints
5. **Enable detailed logging** for PowerShell execution
6. **Implement network segmentation** to limit lateral movement
7. **Regular security awareness training** for users

---

## 📄 Report Files

1. **FINAL_ANSWERS.md** - Complete answers to all exam questions with detailed evidence
2. **EXECUTIVE_SUMMARY.md** - High-level summary for management
3. **QUICK_REFERENCE.md** - Quick lookup sheet for all answers

---

## 🔧 Tools Used

- **Python 3.x** - Analysis scripting
- **IR Network Log Server** - Log data source
- **Base64 Decoder** - Command decoding
- **JSON** - Data processing

---

## 📝 Notes

- All timestamps are in UTC (Z timezone)
- Log IDs are preserved from original dataset
- Network traffic analyzed spans 2025-08-18 from ~01:00Z to ~07:30Z
- Total data exfiltrated: ~750KB via HTTPS alone
- Multiple exfiltration methods indicate sophisticated threat actor

---

## ✍️ Investigation Completed By

Date: November 9, 2025  
Investigation Type: Network Traffic Analysis - Data Exfiltration & C2 Detection  
Total Logs Analyzed: 927  
Investigation Status: ✅ Complete & Verified

---

**For detailed answers, see: `reports/FINAL_ANSWERS.md`**
