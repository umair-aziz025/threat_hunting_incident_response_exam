# WEEK 7 - IR Hunting Report Builder

## Challenge Overview
**Type:** Incident Response Report Creation  
**Server:** `irhuntingreport_windows_amd64.exe` running on `http://127.0.0.1:8080`  
**Cases:** 5 security incidents requiring analyst reports  
**Status:** ✅ **COMPLETED** - All 5 flags captured  

---

## Challenge Description

The IR Hunting Report Builder challenge simulates a real-world incident response scenario where analysts must create comprehensive incident reports for clients. Each case provides:
- **Logs:** Raw security telemetry (ZEEK, Sysmon, EDR, Proxy)
- **Telemetry:** EDR alerts and behavioral indicators
- **Palette:** Suggested report titles, MITRE ATT&CK mappings, impacted hosts/accounts, IOCs
- **Hints:** Analysis guidance for investigators

---

## Incident Cases Summary

### Case 1: DNS Exfiltration via TXT Records
- **Code:** `SCN_DNS_EXFIL`
- **Flag:** `RTL{b88ed147877c1c3769a4fb4823344395}`
- **Attack Vector:** PowerShell script exfiltrating data via DNS TXT queries with base64 encoding
- **Key Evidence:**
  - Base64-encoded TXT queries to `exfil.attacker.com`
  - 200+ DNS TXT requests in burst pattern
  - PowerShell spawned by explorer.exe (suspicious parent)
  - User: `jdoe` on host `ENG-03`
- **MITRE Techniques:** T1071.004, T1132, T1041, T1027, T1568, T1005
- **IOCs:** `exfil.attacker.com`, `8.8.8.8`, TXT records, base64 chunks

### Case 2: ICMP Exfiltration
- **Code:** `SCN_ICMP_EXFIL`
- **Flag:** `RTL{693884d6ed8bdbc22dd24f594da8fb98}`
- **Attack Vector:** Large ICMP echo payloads exfiltrating data via ping
- **Key Evidence:**
  - Ping command with 1400-byte payloads (60 iterations)
  - Target: `203.0.113.45`
  - User: `msmith` on host `WS-07`
- **MITRE Techniques:** T1048, T1095, T1041, T1027
- **IOCs:** `203.0.113.45`, `ping -l 1400`

### Case 3: HTTPS Exfiltration
- **Code:** `SCN_HTTPS_EXFIL`
- **Flag:** `RTL{b06aed4fbb6c0c8d3cd8a2d6749e2b99}`
- **Attack Vector:** Python script uploading 12.8MB file via HTTPS POST
- **Key Evidence:**
  - POST to `cdn-drop.example/upload`
  - File: `C:\Finance\Ledger\Q3.zip` (12.7MB)
  - Non-approved SNI from finance workstation
  - User: `analyst` on host `FIN-11`
  - User-Agent: `python-requests/2.31`
- **MITRE Techniques:** T1041, T1071.001, T1560, T1027
- **IOCs:** `cdn-drop.example`, `198.51.100.120`

### Case 4: HTTP Command & Control
- **Code:** `SCN_C2_HTTP`
- **Flag:** `RTL{e62aa614709b00098ccee79c967870ef}`
- **Attack Vector:** Beaconing malware with command tasking over HTTP
- **Key Evidence:**
  - 60-second beacon intervals to `203.0.113.99`
  - GET `/beacon`, `/task` endpoints
  - Received command: `whoami && ipconfig`
  - POST results back to `/result` (4KB)
  - User: `jdoe` on host `WS-19`
  - Scheduled task persistence
- **MITRE Techniques:** T1071.001, T1059.003, T1053, T1105
- **IOCs:** `203.0.113.99`, `/beacon`, `/task`

### Case 5: HTTPS Command & Control (Encrypted)
- **Code:** `SCN_C2_HTTPS`
- **Flag:** `RTL{193577d2e225015c07fba994502860df}`
- **Attack Vector:** TLS-encrypted C2 with PowerShell encoded commands
- **Key Evidence:**
  - JA3 fingerprint: `769,4865,4867`
  - SNI: `cdn-c2.example`
  - PowerShell encoded command executing `dir C:\`
  - POST to `/b` endpoint (1.2KB payloads)
  - User: `dev.build` on host `LAP-DEV01`
  - User-Agent spoofing: `Chrome/112`
- **MITRE Techniques:** T1071.001, T1059.001, T1573, T1140, T1001
- **IOCs:** `cdn-c2.example`, `198.51.100.200`, JA3 fingerprint

---

## Report Requirements

Each incident report must include the following fields with **specific keywords** to pass validation:

### Required Fields:
1. **Title** - Incident name (must include specific keywords for C2 cases)
2. **Timestamp** - When incident occurred (format: `YYYY-MM-DDTHH:MM:SSZ`)
3. **Description** - Detailed narrative of what happened
4. **MITRE Techniques** - ATT&CK framework mapping
5. **Impacted Hosts** - Affected systems
6. **Impacted Accounts** - Compromised users
7. **IOCs** - Indicators of Compromise
8. **Containment** - Immediate response actions (must include at least 2 specific measures)
9. **Eradication** - Root cause removal (must include at least 2 specific measures)
10. **Recovery** - System restoration steps (must include at least 2 specific measures)

### Validation Keywords by Case:

**Case 1 (DNS Exfiltration):**
- Containment: `isolate`, `block domain`, `sinkhole`, `dns policy`, `edr block`, `quarantine`
- Eradication: `remove script`, `clean powershell`, `profile`, `disable scheduled task`, `delete artifact`
- Recovery: `monitor dns`, `restore network`, `user awareness`, `mfa`, `review`

**Case 2 (ICMP Exfiltration):**
- Eradication: `remove batch`, `policy update`, `script`, `cleanup`
- Recovery: `monitor icmp`, `baseline traffic`, `user awareness`

**Case 3 (HTTPS Exfiltration):**
- Containment: `block sni`, `proxy policy`, `isolate`, `revoke creds`
- Eradication: `remove tool`, `delete script`, `clear persistence`
- Recovery: `rotate passwords`, `data loss assessment`, `monitor tls`

**Case 4 (HTTP C2):**
- Title: Must include keyword `c2`
- Containment: `isolate`, `block egress`, `sinkhole`, `edr block`
- Eradication: `remove scheduled task`, `delete persistence`, `wipe beacon`
- Recovery: `hardening`, `monitor http`, `user reset`

**Case 5 (HTTPS C2):**
- Containment: `isolate`, `cert pinning`, `tls block`, `edr block`
- Eradication: `remove persistence`, `delete script`, `clean registry`
- Recovery: `reset tokens`, `monitor tls`, `hunt similar`

---

## Methodology

### 1. API Reconnaissance
- Started server: `irhuntingreport_windows_amd64.exe`
- Tested various endpoints: `/api/cases`, `/api/case1-5`, `/api/newround`
- All returned HTML, analyzed client-side JavaScript

### 2. Data Extraction
- Discovered correct endpoint: `/api/scenarios`
- Extracted all 5 incident cases with logs, telemetry, palette data
- Saved to `ir_scenarios.json` (219 lines)

### 3. Case Analysis
- Parsed logs to identify attack patterns
- Correlated telemetry with MITRE ATT&CK techniques
- Extracted IOCs, impacted hosts/accounts
- Reviewed hints for analysis guidance

### 4. Report Generation
- Created comprehensive incident reports following IR best practices
- Included all required fields: description, MITRE, IOCs, containment, eradication, recovery
- Ensured specific validation keywords present in each section

### 5. Submission & Validation
- Submitted reports via POST to `/api/submit`
- Initial submissions failed due to missing keywords
- Refined reports based on error messages
- Successfully captured all 5 flags

---

## Scripts Created

### `01_explore_ir_api.py`
- **Purpose:** API endpoint discovery
- **Function:** Tests various endpoints to find data source
- **Result:** All tested endpoints returned HTML

### `02_analyze_html.py`
- **Purpose:** Parse HTML to find JavaScript API calls
- **Function:** Downloads and analyzes page structure with BeautifulSoup
- **Result:** Discovered `/api/scenarios` endpoint in fetch() call

### `03_extract_scenarios.py`
- **Purpose:** Extract all incident cases from API
- **Function:** Fetches JSON from `/api/scenarios`, saves to file
- **Result:** Retrieved 5 complete cases with all data

### `04_analyze_cases.py`
- **Purpose:** Analyze and display case structure
- **Function:** Parses scenarios, displays logs, telemetry, palette, hints
- **Result:** Comprehensive overview of all 5 cases

### `05_generate_reports.py`
- **Purpose:** Generate and submit incident reports
- **Function:** Creates detailed IR reports for each case, submits to API
- **Result:** ✅ All 5 flags captured successfully

---

## Files

- `ir_scenarios.json` - Complete incident case data (5 cases)
- `ir_flags.json` - Captured flags for all cases
- `ir_report_page.html` - Reference HTML interface (13,112 bytes)
- All Python scripts (01-05)

---

## Flags Summary

```
✅ SCN_DNS_EXFIL:   RTL{b88ed147877c1c3769a4fb4823344395}
✅ SCN_ICMP_EXFIL:  RTL{693884d6ed8bdbc22dd24f594da8fb98}
✅ SCN_HTTPS_EXFIL: RTL{b06aed4fbb6c0c8d3cd8a2d6749e2b99}
✅ SCN_C2_HTTP:     RTL{e62aa614709b00098ccee79c967870ef}
✅ SCN_C2_HTTPS:    RTL{193577d2e225015c07fba994502860df}
```

**Total:** 5/5 flags captured (100%)

---

## Key Learnings

1. **API Discovery:** Web interfaces may use JavaScript to fetch data; analyze client-side code to find API endpoints
2. **Validation Requirements:** IR reports require specific keywords for containment, eradication, and recovery actions
3. **MITRE Mapping:** Proper ATT&CK technique mapping is critical for incident classification
4. **IOC Extraction:** Log analysis skills essential for identifying indicators of compromise
5. **IR Process:** Incident response follows structured phases: Detection → Containment → Eradication → Recovery

---

## MITRE ATT&CK Techniques Covered

- **T1071.004** - Application Layer Protocol: DNS
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1132** - Data Encoding
- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1095** - Non-Application Layer Protocol
- **T1027** - Obfuscated Files or Information
- **T1568** - Dynamic Resolution
- **T1005** - Data from Local System
- **T1560** - Archive Collected Data
- **T1059.003** - Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1053** - Scheduled Task/Job
- **T1105** - Ingress Tool Transfer
- **T1573** - Encrypted Channel
- **T1140** - Deobfuscate/Decode Files or Information
- **T1001** - Data Obfuscation

---

## Challenge Completion

✅ **Status:** COMPLETED  
✅ **Flags:** 5/5 (100%)  
✅ **Date:** November 9, 2025  
✅ **Time Invested:** ~2 hours  

**Difficulty:** Medium - Requires understanding of incident response processes, log analysis, and MITRE ATT&CK framework.
