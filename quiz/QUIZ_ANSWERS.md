# IR Hunting Report Builder - Quiz Answers

## Security Knowledge Assessment - Answers

Based on the IR Hunting Report Builder challenge (WEEK 7) and incident response best practices:

---

### Question 1: In a structured hunting cycle, what should come first?
**Answer: Hypothesis**

**Explanation:** 
The threat hunting cycle follows: Hypothesis → Investigation → Detection → Response
- You must form a hypothesis based on threat intelligence or anomalies
- Then investigate to prove/disprove it
- Containment and Eradication come AFTER detection during incident response

---

### Question 2: You suspect DNS TXT exfiltration. Which data source is MOST critical to confirm it?
**Answer: DNS resolver logs (query/response)**

**Explanation:**
From Case 1 (SCN_DNS_EXFIL) we analyzed:
```
ZEEK_DNS ENG-03 10.10.23.44 → 8.8.8.8 TXT 
qname=c3VwZXJzZWNyZXQxLmZpbGUucGFydC4xLmV4ZmlsLmF0dGFja2VyLmNvbQ==.exfil.attacker.com
```
- DNS resolver logs show the actual TXT queries with base64-encoded data
- You can see query names, response data, and patterns
- NetFlow only shows byte counts (not query content)
- DHCP and ARP are not relevant for DNS exfiltration

---

### Question 3: Windows process that holds authentication secrets and Kerberos tickets:
**Answer: lsass.exe (Local Security Authority Subsystem Service)**

**Explanation:**
- LSASS stores credentials, password hashes, and Kerberos tickets in memory
- Common target for credential dumping attacks (Mimikatz, ProcDump)
- As mentioned in Quiz Question 11: "LSASS dump on a domain controller" is critical

---

### Question 4: PowerShell with -EncodedCommand maps primarily to which MITRE technique?
**Answer: T1059.001**

**Explanation:**
From Case 5 (SCN_C2_HTTPS) we mapped:
- **T1059.001** - Command and Scripting Interpreter: PowerShell
```
powershell.exe -nop -w hidden -enc SQB... 
(decoded: Invoke-Command 'dir C:\')
```
Other options:
- T1003.001 = Credential Dumping (LSASS)
- T1071.004 = Application Layer Protocol: DNS
- T1105 = Ingress Tool Transfer

---

### Question 5: A good signal for HTTP beaconing is:
**Answer: Inter-arrival periodicity of requests**

**Explanation:**
From Case 4 (SCN_C2_HTTP):
```
2025-07-26T03:04:11Z PROXY WS-19 → 203.0.113.99 
GET /beacon?id=WS-19&v=1.2 (interval 60s)
```
- Periodic requests at fixed intervals (e.g., every 60 seconds) indicate beaconing
- C2 malware typically checks in at regular intervals
- Random URI lengths, DNS TTL, and MSS values are not reliable indicators

---

### Question 6: During active credential theft on a workstation, your FIRST containment action should most often be:
**Answer: Isolate the affected host from the network**

**Explanation:**
From our IR reports, Containment phase always started with:
```
"Isolate host from network immediately"
```
- Prevents lateral movement to other systems
- Stops credential exfiltration in progress
- Rotating passwords comes AFTER containment
- Never disable SIEM rules
- Wiping disk destroys forensic evidence

---

### Question 7: Common Sysinternals tool used to dump process memory for troubleshooting:
**Answer: ProcDump**

**Explanation:**
- ProcDump creates memory dumps of running processes
- Commonly used legitimately for troubleshooting
- Also abused by attackers to dump LSASS for credentials
- Example: `procdump.exe -ma lsass.exe lsass.dmp`

Other Sysinternals tools: Process Explorer, Autoruns, TCPView, etc.

---

### Question 8: Windows Security Event ID for Kerberos service ticket requests is:
**Answer: 4769**

**Explanation:**
Windows Security Event IDs:
- **4624** = Successful logon
- **4688** = Process creation (used in our logs: SYS_4688)
- **4769** = Kerberos service ticket (TGS) request
- **4662** = Operation performed on object

---

### Question 9: Which KQL fragment best narrows to PowerShell ScriptBlock logs with encoded commands in Microsoft 365 Defender?
**Answer: EventID == 4104 and Message contains "EncodedCommand"**

**Explanation:**
- **Event ID 4104** = PowerShell Script Block Logging
- Captures the actual script content being executed
- Can detect encoded commands in the script block

Other options:
- 4688 = Process creation (command line, but not script content)
- 4625 = Failed logon
- 3 = Sysmon Network Connection

---

### Question 10: IR phase focused on removing malware, tooling, and persistence:
**Answer: Eradication**

**Explanation:**
From our IR reports, the three phases are:
1. **Containment** - Stop the bleeding (isolate, block)
2. **Eradication** - Remove root cause (delete malware, remove persistence, clean registry)
3. **Recovery** - Restore normal operations (monitor, harden, restore access)

Case 4 Eradication example:
```
"Remove scheduled task persistence. 
Delete persistence from registry Run keys. 
Wipe beacon.exe malware from disk."
```

---

### Question 11: Which finding is MOST critical and time-sensitive?
**Answer: LSASS dump on a domain controller**

**Explanation:**
**Critical Severity Ranking:**
1. **LSASS dump on DC** - CRITICAL (entire domain compromise imminent)
   - Contains all domain credentials and Kerberos keys
   - Attacker can create Golden Tickets
   - Immediate domain-wide impact

2. Periodic GET to /beacon from kiosk - High (active C2, needs response)
3. Five failed logons - Medium (possible brute force)
4. Blocked phishing email - Low (successfully blocked)

**Time-Sensitive Reasoning:**
- Domain Controller compromise = Enterprise-level breach
- Credentials for ALL domain accounts at risk
- Must isolate immediately and investigate scope
- Potential for Golden Ticket attacks (T1558.001)

---

## Quiz Performance Summary

**Total Questions:** 11  
**Subject Areas:**
- Threat Hunting Methodology (1)
- Log Analysis & Data Sources (2)
- Windows Internals (2)
- MITRE ATT&CK Framework (1)
- C2 Detection (1)
- Incident Response Process (2)
- Security Event IDs (1)
- Threat Prioritization (1)

**Knowledge Applied From Challenge:**
- Case 1: DNS TXT exfiltration analysis
- Case 4: HTTP beaconing detection
- Case 5: PowerShell encoded commands
- All cases: IR methodology (Containment → Eradication → Recovery)

---

## Answer Key (Quick Reference)

1. **Hypothesis** (hunting cycle starts with hypothesis)
2. **DNS resolver logs** (shows TXT queries and responses)
3. **lsass.exe** (holds credentials and Kerberos tickets)
4. **T1059.001** (PowerShell scripting interpreter)
5. **Inter-arrival periodicity** (fixed interval beaconing)
6. **Isolate the host** (first containment action)
7. **ProcDump** (Sysinternals memory dump tool)
8. **4769** (Kerberos service ticket request)
9. **EventID == 4104 and Message contains "EncodedCommand"** (ScriptBlock logs)
10. **Eradication** (removal of malware and persistence)
11. **LSASS dump on DC** (most critical - domain compromise)

---

## Validation Against Our Challenge

These answers directly correlate to our IR Hunting Report Builder findings:

✅ **DNS Exfiltration (Case 1):** Used ZEEK_DNS logs to identify TXT queries  
✅ **HTTP Beaconing (Case 4):** Detected 60-second periodic requests  
✅ **PowerShell Encoding (Case 5):** Identified T1059.001 with -enc flag  
✅ **IR Methodology:** Applied Containment → Eradication → Recovery to all cases  
✅ **Threat Prioritization:** Analyzed severity of different attack types  

**Date:** November 9, 2025  
**Challenge Reference:** WEEK 7 - IR Hunting Report Builder  
**Knowledge Base:** CTHIRI_Investigation_Complete
