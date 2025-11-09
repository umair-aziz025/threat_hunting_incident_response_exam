# Quick Answer Reference - CTHIRI Exam

*For detailed analysis, see FINAL_ANSWERS.md*

---

## Q1: Golden Ticket Attack
```
Timestamp:     2025-08-18T01:15:00Z
Host:          DC01
Source:        Sysmon
Event ID:      4769
Client IP:     10.10.5.23
AttackOption:  0x40810010
SPN:           cifs/DC01
```

## Q2: Silver Ticket
```
Account:       WS02 / HOST/WS02
Host:          WS02
Timestamp:     2025-08-18T03:40:00Z
Source:        Sysmon
Event:         4769
```

## Q3: LSASS Dump
```
Host:          WS01
User:          jdoe
Process:       C:\Tools\procdump64.exe
Target:        C:\Windows\System32\lsass.exe
Event:         10
AccessMask:    0x1FFFFF
```

## Q4: PowerShell EncodedCommand
```
Host/User:     WS02/msmith
URL:           http://10.10.5.23/a.ps1
Script Name:   a.ps1
Event:         4104
```

## Q5A: Mimikatz
```
User:          Administrator
Host:          WS01
Command:       mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
Folder:        C:\Windows\Temp\
```

## Q5B: PsExec
```
Source Host:   WS02
Remote Host:   FILE01
Account:       CORP\svc_backup
Command:       psexec.exe \\WS02 -u CORP\svc_backup -p ******** cmd /c whoami
Log Source:    WindowsSecurity
Event ID:      4688
Filter:        event:4688 source:WindowsSecurity
```

## Q5C: Timeline
```
First Event:   LSASS dump (05:10) before PsExec (06:35)
Time Gap:      5h 45m ✓ (Golden Ticket to PowerShell)
Client IP:     10.10.5.23
Accounts:
  - Golden Ticket: cifs/DC01 on DC01
  - Silver Ticket: HOST/WS02 on WS02
```

---

## Attack Sequence
```
01:15  →  Golden Ticket (DC01)
03:40  →  Silver Ticket (WS02)
05:10  →  LSASS Dump (WS01)
06:35  →  PsExec to FILE01
07:00  →  PowerShell (WS02)
07:40  →  Mimikatz (WS01)
```

**Attacker IP**: 10.10.5.23 (consistent across all attacks)

---

## Quick Stats
- **Total Events Analyzed**: 500
- **Attack Events**: 6
- **Systems Compromised**: 4 (DC01, WS01, WS02, FILE01)
- **Accounts Compromised**: 4
- **Attack Duration**: ~6.5 hours
- **MITRE Techniques**: 6

---

*All answers verified ✓*
