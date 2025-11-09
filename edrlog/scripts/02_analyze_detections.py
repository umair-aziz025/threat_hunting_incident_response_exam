import json

print("=" * 80)
print("EDR DETECTION ANALYSIS - TRUE POSITIVE vs FALSE POSITIVE")
print("=" * 80)

# Load detections
with open('edr_detections.json', 'r') as f:
    detections = json.load(f)

print(f"\n[*] Analyzing {len(detections)} detections...\n")

# Analysis results
malicious = []
benign = []

# Analyze each detection
for i, det in enumerate(detections, 1):
    print("=" * 80)
    print(f"DETECTION #{i}: {det['title']}")
    print("=" * 80)
    
    title = det['title']
    category = det['category']
    severity = det['severity']
    image = det['image']
    cmd = det['command_line']
    notes = det['notes']
    mitre = det.get('mitre', [])
    kill_chain = det.get('kill_chain', [])
    user = det['user']
    host = det['host']
    process_tree = det.get('process_tree', [])
    exec_flow = det.get('exec_flow', [])
    
    print(f"Category: {category}")
    print(f"Severity: {severity}")
    print(f"Host: {host}")
    print(f"User: {user}")
    print(f"Image: {image}")
    print(f"Command: {cmd}")
    print(f"MITRE: {', '.join(mitre)}")
    print(f"Kill Chain: {', '.join(kill_chain)}")
    print(f"Process Tree: {' -> '.join(process_tree)}")
    print(f"Exec Flow: {', '.join(exec_flow)}")
    print(f"Notes: {notes}")
    
    # Decision logic
    is_malicious = False
    reason = ""
    
    # MALICIOUS INDICATORS
    
    # 1. Explicit malicious behavior
    if 'malicious' in title.lower() or 'evil' in cmd.lower():
        is_malicious = True
        reason = "Explicit malicious activity mentioned"
    
    # 2. BYOVD with unsigned loader
    elif 'Unsigned loader' in title and 'BYOVD' in title:
        is_malicious = True
        reason = "Unsigned loader installing vulnerable driver (BYOVD attack)"
    
    # 3. Code injection into uncommon targets
    elif 'injection' in title.lower() and 'notepad.exe' in title.lower():
        is_malicious = True
        reason = "Code injection into notepad.exe (suspicious target)"
    
    # 4. Unknown malicious tools
    elif 'Hookchain.exe' in title:
        is_malicious = True
        reason = "Hookchain.exe - known injection tool"
    
    # 5. Dropper behavior
    elif 'Dropper' in title and 'second-stage payload' in title:
        is_malicious = True
        reason = "Dropper staging second-stage payload"
    
    # 6. LSASS dumping
    elif 'LSASS' in title or ('minidump' in image.lower() and 'credential' in category.lower()):
        is_malicious = True
        reason = "LSASS memory dumping (credential theft)"
    
    # 7. LOLBINs with malicious MITRE tactics
    elif 'LOLBIN' in category:
        # Check for benign LOLBIN usage first (more specific checks)
        if 'verifies certificate chain' in title.lower():
            is_malicious = False
            reason = "Certutil verifying certificates (legitimate VPN)"
        elif 'registers vendor DLL (signed)' in title.lower():
            is_malicious = False
            reason = "Regsvr32 registering signed vendor DLL"
        elif 'corporate enrollment page' in title.lower():
            is_malicious = False
            reason = "Mshta loading corporate enrollment (IT process)"
        elif 'Control Panel applet' in title.lower():
            is_malicious = False
            reason = "Rundll32 opening Control Panel (standard Windows)"
        elif 'used by Windows Update' in title.lower():
            is_malicious = False
            reason = "Bitsadmin used by Windows Update (system process)"
        # Check for malicious patterns
        elif 'remote payload' in title.lower() or 'T1105' in ' '.join(mitre):
            is_malicious = True
            reason = "LOLBIN downloading remote payload"
        elif 'remote scrobj COM script' in title.lower() or 'T1218.010' in ' '.join(mitre):
            is_malicious = True
            reason = "Regsvr32 executing remote COM script"
        elif 'remote HTA executing commands' in title.lower() or ('T1218.005' in ' '.join(mitre) and 'http://' in cmd):
            is_malicious = True
            reason = "Mshta loading remote HTA with commands"
        elif 'transfers staged binary' in title.lower() or 'T1197' in ' '.join(mitre):
            is_malicious = True
            reason = "Bitsadmin transferring staged binary"
    
    # BENIGN INDICATORS
    
    # 1. Legitimate dev tooling
    if not is_malicious and 'Dev pipeline' in title:
        is_malicious = False
        reason = "MSBuild in CI/CD pipeline (expected dev process)"
    
    # 2. IT troubleshooting on IIS
    if not is_malicious and 'ProcDump' in title and 'w3wp.exe' in title:
        is_malicious = False
        reason = "ProcDump on IIS w3wp.exe for troubleshooting (legitimate IT)"
    
    # 3. Backup agents
    if not is_malicious and 'Backup agent' in title:
        is_malicious = False
        reason = "Backup agent performing scheduled backup (expected behavior)"
    
    # 4. Signed vendor driver updates
    if not is_malicious and 'Driver update utility' in title and 'vendor-signed' in title:
        is_malicious = False
        reason = "Vendor-signed driver update (legitimate maintenance)"
    
    # 5. IT remote admin tools
    if not is_malicious and 'Remote admin tool' in title and 'patch' in title:
        is_malicious = False
        reason = "IT remote admin tool pushing patches (legitimate IT ops)"
    
    # Final categorization
    print(f"\n{'='*80}")
    if is_malicious:
        print(f"VERDICT: [MALICIOUS] - TRUE POSITIVE")
        print(f"REASON: {reason}")
        malicious.append(i)
    else:
        print(f"VERDICT: [BENIGN] - FALSE POSITIVE")
        print(f"REASON: {reason}")
        benign.append(i)
    print(f"{'='*80}\n")

# Summary
print("\n" + "=" * 80)
print("ANALYSIS SUMMARY")
print("=" * 80)

print(f"\nMALICIOUS DETECTIONS (True Positives): {len(malicious)}")
for num in malicious:
    det = detections[num-1]
    print(f"  [{num}] {det['title']}")

print(f"\nBENIGN DETECTIONS (False Positives): {len(benign)}")
for num in benign:
    det = detections[num-1]
    print(f"  [{num}] {det['title']}")

# Generate RTL{} format
print("\n" + "=" * 80)
print("ANSWER FORMAT")
print("=" * 80)

answer = "RTL{" + ",".join(map(str, sorted(malicious))) + "}"
print(f"\nRTL Format Answer: {answer}")

# Save analysis
with open('edr_analysis.json', 'w') as f:
    json.dump({
        'malicious': malicious,
        'benign': benign,
        'answer': answer
    }, f, indent=2)

print(f"\n[✓] Analysis saved to: edr_analysis.json")
print("\n" + "=" * 80)
