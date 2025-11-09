# FLAGS - IR Hunting Report Builder

## Challenge: WEEK 7 - IR Hunting Report Builder
**Date:** November 9, 2025  
**Status:** ✅ COMPLETED (5/5 flags)

---

## Captured Flags

### Case 1: DNS Exfiltration via TXT Records
**Code:** `SCN_DNS_EXFIL`  
**Flag:** `RTL{b88ed147877c1c3769a4fb4823344395}`  
**Status:** ✅ Verified

**Attack Summary:**
- PowerShell script exfiltrating data via DNS TXT queries
- Base64-encoded query names to exfil.attacker.com
- User: jdoe on host ENG-03
- 200+ DNS requests in burst pattern

---

### Case 2: ICMP Exfiltration
**Code:** `SCN_ICMP_EXFIL`  
**Flag:** `RTL{693884d6ed8bdbc22dd24f594da8fb98}`  
**Status:** ✅ Verified

**Attack Summary:**
- Large ICMP echo payloads (1400 bytes)
- 60 pings to external IP 203.0.113.45
- User: msmith on host WS-07
- Command: `ping -n 60 -l 1400`

---

### Case 3: HTTPS Exfiltration
**Code:** `SCN_HTTPS_EXFIL`  
**Flag:** `RTL{b06aed4fbb6c0c8d3cd8a2d6749e2b99}`  
**Status:** ✅ Verified

**Attack Summary:**
- Python script uploading 12.8MB financial file
- POST to cdn-drop.example via HTTPS
- User: analyst on host FIN-11
- File: C:\Finance\Ledger\Q3.zip

---

### Case 4: HTTP Command & Control
**Code:** `SCN_C2_HTTP`  
**Flag:** `RTL{e62aa614709b00098ccee79c967870ef}`  
**Status:** ✅ Verified

**Attack Summary:**
- HTTP beaconing malware with 60s intervals
- C2 server: 203.0.113.99
- Commands received via /task endpoint
- User: jdoe on host WS-19
- Persistence: Scheduled task

---

### Case 5: HTTPS Command & Control (Encrypted)
**Code:** `SCN_C2_HTTPS`  
**Flag:** `RTL{193577d2e225015c07fba994502860df}`  
**Status:** ✅ Verified

**Attack Summary:**
- TLS-encrypted C2 with JA3 fingerprint 769,4865,4867
- SNI: cdn-c2.example
- PowerShell encoded commands
- User: dev.build on host LAP-DEV01

---

## Flag Summary

```
Total Cases:      5
Flags Captured:   5
Success Rate:     100%
```

### All Flags:
```
SCN_DNS_EXFIL   → RTL{b88ed147877c1c3769a4fb4823344395}
SCN_ICMP_EXFIL  → RTL{693884d6ed8bdbc22dd24f594da8fb98}
SCN_HTTPS_EXFIL → RTL{b06aed4fbb6c0c8d3cd8a2d6749e2b99}
SCN_C2_HTTP     → RTL{e62aa614709b00098ccee79c967870ef}
SCN_C2_HTTPS    → RTL{193577d2e225015c07fba994502860df}
```

---

## Validation Method

Flags were captured by submitting comprehensive incident response reports to the API endpoint `/api/submit` with the following required fields:

- **Title:** Incident name
- **Timestamp:** Incident date/time
- **Description:** Detailed attack narrative
- **MITRE Techniques:** ATT&CK framework mapping
- **Impacted Hosts:** Compromised systems
- **Impacted Accounts:** Affected users
- **IOCs:** Indicators of Compromise
- **Containment:** Immediate response actions (with specific keywords)
- **Eradication:** Root cause removal (with specific keywords)
- **Recovery:** System restoration steps (with specific keywords)

Each report required specific validation keywords in the containment, eradication, and recovery sections to pass validation and reveal the flag.

---

## Challenge Completion

✅ **All challenges completed successfully**  
✅ **5/5 flags captured (100%)**  
✅ **All reports validated**  
✅ **Investigation documented**  

**Date Completed:** November 9, 2025  
**Analyst:** Umair Aziz
