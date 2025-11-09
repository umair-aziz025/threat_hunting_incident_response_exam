# Quick Reference - Exam Answers
## Network Traffic Analysis Challenge

---

## DNS EXFILTRATION

| Question | Answer |
|----------|--------|
| **DNS exfil source host?** | `10.0.5.50` |
| **DNS exfil base domain?** | `exfil.attacker.net` |
| **DNS exfil query types used?** | `A, TXT` |
| **DNS exfil destination (resolver) IP?** | `10.0.0.53` |
| **HOST/DNS/SNI with largest data exfiltration size?** | `secure-updates.cdn-cloudsync.net` (750,000 bytes) |

---

## ICMP EXFILTRATION

| Question | Answer |
|----------|--------|
| **ICMP exfil source?** | `10.0.5.51` |
| **ICMP exfil destination?** | `198.51.100.10` |
| **ICMP exfil type request?** | `echo-request` |
| **What type of encode is being used to exfiltrate data via ICMP?** | `Base64` |

---

## HTTPS EXFILTRATION

| Question | Answer |
|----------|--------|
| **HTTPS exfil request method?** | `POST` |
| **HTTPS exfil URI?** | `/sync/upload` |
| **HTTPS exfil data size bytes?** | `150000` |
| **HTTPS exfil domain or host?** | `secure-updates.cdn-cloudsync.net` |

---

## DNS FILTER

| Question | Answer |
|----------|--------|
| **Create a filter for exfil.attacker.net domain** | `app:DNS qtype:TXT qname:exfil.attacker.net` |

---

## C2 DETECTION

| Question | Answer |
|----------|--------|
| **C2 over protocol?** | `HTTP` |
| **C2 over HTTP source IP?** | `10.0.5.40` |
| **C2 over HTTP destination IP?** | `203.0.113.55` |
| **C2 over HTTP Host?** | `update-service.net` |
| **What command did HTTP C2 execute at 04:30:10Z?** | `cmd:whoami` |
| **C2 HTTP user-agent string used?** | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.3` |
| **C2 over HTTPS source IP?** | `10.0.5.30` |
| **C2 over HTTPS SNI?** | `cdn-cloudupdates.net` |
| **C2 over HTTPS destination IP?** | `198.51.100.23` |
| **Write at least one of the endpoints used by c2?** | `/api/beacon` (or `/api/task`, `/api/result`) |

---

## COPY-PASTE FORMAT

```
DNS Exfil Source: 10.0.5.50
DNS Exfil Domain: exfil.attacker.net
DNS Query Types: A, TXT
DNS Resolver: 10.0.0.53
Largest Exfil Host: secure-updates.cdn-cloudsync.net

ICMP Source: 10.0.5.51
ICMP Destination: 198.51.100.10
ICMP Type: echo-request
ICMP Encoding: Base64

HTTPS Method: POST
HTTPS URI: /sync/upload
HTTPS Size: 150000
HTTPS Host: secure-updates.cdn-cloudsync.net

DNS Filter: app:DNS qtype:TXT qname:exfil.attacker.net

C2 Protocol: HTTP
HTTP C2 Source: 10.0.5.40
HTTP C2 Destination: 203.0.113.55
HTTP C2 Host: update-service.net
Command at 04:30:10Z: cmd:whoami
HTTP User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.3
HTTPS C2 Source: 10.0.5.30
HTTPS C2 SNI: cdn-cloudupdates.net
HTTPS C2 Destination: 198.51.100.23
C2 Endpoint: /api/beacon
```

---

## VERIFICATION STATUS

✅ All answers verified against 927 network logs  
✅ 22/22 checks passed  
✅ 100% success rate

---

## QUICK IOCs

**Malicious Domains:**
- exfil.attacker.net
- update-service.net
- cdn-cloudupdates.net
- secure-updates.cdn-cloudsync.net

**Malicious IPs:**
- 203.0.113.55
- 203.0.113.200
- 198.51.100.23
- 198.51.100.10

**Compromised Hosts:**
- 10.0.5.50
- 10.0.5.51
- 10.0.5.60
- 10.0.5.40
- 10.0.5.30
