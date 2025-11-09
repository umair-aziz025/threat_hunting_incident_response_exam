# Network Traffic Analysis - Exam Answers
## Data Exfiltration & C2 Detection Challenge

---

## SECTION 1: DNS EXFILTRATION

### Q1: DNS exfil source host?
**Answer:** `10.0.5.50`

### Q2: DNS exfil base domain?
**Answer:** `exfil.attacker.net`

### Q3: DNS exfil query types used?
**Answer:** `A, TXT`

### Q4: DNS exfil destination (resolver) IP?
**Answer:** `10.0.0.53`

### Q5: What is HOST/DNS/SNI with the largest data exfiltration size?
**Answer:** `secure-updates.cdn-cloudsync.net`
- Total Size: 750,000 bytes
- Protocol: HTTPS
- Method: POST requests (5 total)

**Evidence:** 
- Found 6 DNS exfiltration queries to `data.exfil.attacker.net` subdomain
- Example queries:
  - `k28i23ew.4f2f7061727436.data.exfil.attacker.net` (TXT)
  - `46vt67b3.4e2f7061727435.data.exfil.attacker.net` (TXT)
  - `dd7gaowu.4d2f7061727434.data.exfil.attacker.net` (A)

---

## SECTION 2: ICMP EXFILTRATION

### Q6: ICMP exfil source?
**Answer:** `10.0.5.51`

### Q7: ICMP exfil destination?
**Answer:** `198.51.100.10`

### Q8: ICMP exfil type request?
**Answer:** `echo-request`

### Q9: What type of encode is being used to exfiltrate data via ICMP?
**Answer:** `Base64`

**Evidence:**
- Found 8 suspicious ICMP packets (size > 100 bytes, normal ping is ~64-98 bytes)
- Average packet size: 682 bytes
- Sample payload: `Qm2gYmdUrsktJHSl7PeMxPf+O0o707yzC9FO/mfSInS5gXkkffESZyjKs8XnyL8flZ4haU8piaE6dUL1...`
- Payload contains Base64 characters (A-Z, a-z, 0-9, +, /, =)
- All 8 packets from 10.0.5.51 to 198.51.100.10
- Timestamps: Between 02:20:00Z and 02:22:06Z

---

## SECTION 3: HTTPS EXFILTRATION

### Q10: HTTPS exfil request method?
**Answer:** `POST`

### Q11: HTTPS exfil URI?
**Answer:** `/sync/upload`

### Q12: HTTPS exfil data size bytes?
**Answer:** `150000` (bytes)

### Q13: HTTPS exfil domain or host?
**Answer:** `secure-updates.cdn-cloudsync.net`

**Evidence:**
- Log ID: 475
- Timestamp: 2025-08-18T03:47:40Z
- Source: 10.0.5.60
- Destination: 203.0.113.200
- Port: 443 (HTTPS)
- This is the single largest HTTPS transfer in the logs

### Q14: Create a filter for exfil.attacker.net domain
**Answer:** `app:DNS qtype:TXT qname:exfil.attacker.net`

Alternative filters:
- `app:DNS qname:exfil.attacker.net` (all query types)
- `app:DNS qtype:A qname:exfil.attacker.net` (A records only)

---

## SECTION 4: C2 (COMMAND & CONTROL) DETECTION

### Q15: C2 over protocol?
**Answer:** `HTTP`

### Q16: C2 over HTTP source IP?
**Answer:** `10.0.5.40`

### Q17: C2 over HTTP destination IP?
**Answer:** `203.0.113.55`

### Q18: C2 over HTTP Host?
**Answer:** `update-service.net`

### Q19: What command did HTTP C2 execute at 04:30:10Z?
**Answer:** `cmd:whoami`

**Evidence:**
- Encoded payload: `Y21kOndob2FtaQ==`
- Base64 decoded: `cmd:whoami`
- URI: `/api/task`
- Method: GET

### Q20: C2 HTTP user-agent string used?
**Answer:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.3`

### Q21: C2 over HTTPS source IP?
**Answer:** `10.0.5.30`

### Q22: C2 over HTTPS SNI?
**Answer:** `cdn-cloudupdates.net`

### Q23: C2 over HTTPS destination IP?
**Answer:** `198.51.100.23`

### Q24: Write at least one of the endpoints used by c2?
**Answer:** `/api/beacon` (or `/api/task`, `/api/result`)

**HTTP C2 Evidence:**
- Host: `update-service.net`
- Connection count: 5 requests
- Endpoints:
  - `/api/beacon` - C2 beaconing
  - `/api/task` - Receive tasks/commands
  - `/api/result` - Submit results
- Methods: POST (3), GET (2)
- User-Agent: PowerShell-based

**HTTPS C2 Evidence:**
- SNI/Host: `cdn-cloudupdates.net`
- Connection count: 3 requests
- Endpoints:
  - `/v1/checkin` - Check in with C2
  - `/v1/tasks` - Receive tasks
  - `/v1/results` - Submit results
- Methods: POST (2), GET (1)

---

## SUMMARY OF FINDINGS

### Data Exfiltration Activities:

1. **DNS Exfiltration**
   - Source: 10.0.5.50
   - Method: TXT and A record queries to `data.exfil.attacker.net`
   - Encoded data in subdomains
   - 6 total queries identified

2. **ICMP Tunneling**
   - Source: 10.0.5.51
   - Destination: 198.51.100.10
   - Method: Base64-encoded data in ICMP echo requests
   - 8 large packets identified (avg 682 bytes)

3. **HTTPS Exfiltration**
   - Source: 10.0.5.60
   - Host: secure-updates.cdn-cloudsync.net
   - Method: Large POST requests to `/sync/upload`
   - Single largest transfer: 150,000 bytes
   - Total exfiltration: 750,000 bytes across 5 requests

### Command & Control (C2) Activities:

1. **HTTP C2**
   - Compromised host: 10.0.5.40
   - C2 Server: update-service.net (203.0.113.55)
   - Communication pattern: Beaconing with task retrieval
   - Command executed: `cmd:whoami` at 04:30:10Z
   - User-Agent: PowerShell 7.3

2. **HTTPS C2**
   - Compromised host: 10.0.5.30
   - C2 Server: cdn-cloudupdates.net (198.51.100.23)
   - Communication pattern: Check-in, task retrieval, result submission
   - Disguised as legitimate CDN traffic

### Attack Timeline:
- DNS Exfiltration: ~01:00:00Z - 01:02:05Z
- ICMP Exfiltration: ~02:20:00Z - 02:22:06Z
- HTTPS Exfiltration: ~03:47:40Z (largest single transfer)
- HTTP C2 Activity: ~04:30:10Z (command execution)

### Indicators of Compromise (IOCs):

**Malicious Domains:**
- exfil.attacker.net
- update-service.net
- cdn-cloudupdates.net
- secure-updates.cdn-cloudsync.net

**Malicious IPs:**
- 203.0.113.55 (HTTP C2 server)
- 203.0.113.200 (HTTPS exfil server)
- 198.51.100.23 (HTTPS C2 server)
- 198.51.100.10 (ICMP exfil destination)

**Compromised Internal Hosts:**
- 10.0.5.50 (DNS exfiltration)
- 10.0.5.51 (ICMP exfiltration)
- 10.0.5.60 (HTTPS exfiltration)
- 10.0.5.40 (HTTP C2 communication)
- 10.0.5.30 (HTTPS C2 communication)

---

## Analysis Completed
- Total network logs analyzed: 927
- Suspicious activities identified: 22 events
- Compromised hosts: 5
- Exfiltration methods: 3 (DNS, ICMP, HTTPS)
- C2 channels: 2 (HTTP, HTTPS)
