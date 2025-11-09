import json

print("=" * 80)
print("DEEP RE-ANALYSIS - VERIFYING EACH DETECTION")
print("=" * 80)

# Load detections
with open('edr_detections.json', 'r') as f:
    detections = json.load(f)

# Map question titles to detection data
question_order = [
    "Unsigned loader installs vulnerable signed driver (BYOVD)",
    "DLL injection into notepad.exe using CreateRemoteThread",
    "Dropper downloads and stages second-stage payload",
    "LSASS memory dump via alternate method (mimikatz variant)",
    "Hookchain.exe injects code into explorer.exe",
    "LOLBIN: certutil downloads remote payload",
    "LOLBIN: regsvr32 executes remote scrobj COM script",
    "LOLBIN: mshta loads remote HTA executing commands",
    "LOLBIN: bitsadmin transfers staged binary",
    "LOLBIN: installutil runs malicious assembly",
    "Backup agent bulk file reads & HTTPS upload to cloud",
    "Driver update utility installing vendor-signed driver",
    "ProcDump used to capture w3wp.exe for troubleshooting",
    "MSBuild post-build PowerShell script (Dev pipeline)",
    "Remote admin tool pushes patch via PsExec-like service",
    "LOLBIN: certutil verifies certificate chain for VPN",
    "LOLBIN: regsvr32 registers vendor DLL (signed",
    "LOLBIN: mshta launches corporate enrollment page",
    "LOLBIN: rundll32 opens Control Panel applet",
    "LOLBIN: bitsadmin used by Windows Update"
]

results = []

for idx, question in enumerate(question_order, 1):
    print(f"\n{'='*80}")
    print(f"QUESTION {idx}: {question}")
    print('='*80)
    
    # Find matching detection
    det = None
    for d in detections:
        if question in d['title'] or d['title'] in question:
            det = d
            break
    
    if not det:
        print("❌ DETECTION NOT FOUND!")
        continue
    
    # Display full telemetry
    print(f"\n📊 FULL TELEMETRY:")
    print(f"  ID: {det['id']}")
    print(f"  Title: {det['title']}")
    print(f"  Category: {det['category']}")
    print(f"  Severity: {det['severity']}")
    print(f"  Host: {det['host']}")
    print(f"  User: {det['user']}")
    print(f"  Image: {det['image']}")
    print(f"  Command: {det['command_line']}")
    print(f"  MITRE: {', '.join(det.get('mitre', []))}")
    print(f"  Kill Chain: {', '.join(det.get('kill_chain', []))}")
    print(f"  Process Tree: {' -> '.join(det.get('process_tree', []))}")
    print(f"  Exec Flow: {', '.join(det.get('exec_flow', []))}")
    print(f"  Notes: {det['notes']}")
    
    # Critical analysis
    print(f"\n🔍 CRITICAL ANALYSIS:")
    
    is_malicious = None
    reasoning = []
    
    # MALICIOUS INDICATORS
    if 'evil' in det['command_line'].lower():
        reasoning.append("❌ MALICIOUS: Filename contains 'evil.dll'")
        is_malicious = True
    
    if 'unsigned' in det['title'].lower() and 'loader' in det['title'].lower():
        reasoning.append("❌ MALICIOUS: Unsigned loader (BYOVD attack)")
        is_malicious = True
    
    if 'LSASS' in det['title'] or 'lsass' in det['command_line'].lower():
        if 'w3wp' not in det['command_line'].lower():
            reasoning.append("❌ MALICIOUS: LSASS credential dumping")
            is_malicious = True
    
    if 'injection' in det['title'].lower() or 'inject' in det['title'].lower():
        if 'notepad' in det['title'].lower():
            reasoning.append("❌ MALICIOUS: Code injection into notepad")
            is_malicious = True
    
    if 'Hookchain' in det['image']:
        reasoning.append("❌ MALICIOUS: Known injection tool Hookchain.exe")
        is_malicious = True
    
    if 'Dropper' in det['category']:
        reasoning.append("❌ MALICIOUS: Dropper staging payload")
        is_malicious = True
    
    # Check for remote payload downloads
    if det['category'].startswith('LOLBIN'):
        cmd = det['command_line'].lower()
        
        # Malicious LOLBIN patterns
        if 'certutil' in det['image'].lower():
            if '-urlcache' in cmd or 'http://' in cmd:
                reasoning.append("❌ MALICIOUS: Certutil downloading remote payload")
                is_malicious = True
            elif '-verify' in cmd:
                reasoning.append("✅ BENIGN: Certutil verifying certificate")
                is_malicious = False
        
        elif 'regsvr32' in det['image'].lower():
            if 'http://' in cmd or 'remote' in det['title'].lower():
                reasoning.append("❌ MALICIOUS: Regsvr32 remote scriptlet execution")
                is_malicious = True
            elif 'vendor' in det['title'].lower() and 'signed' in det['title'].lower():
                reasoning.append("✅ BENIGN: Registering signed vendor DLL")
                is_malicious = False
        
        elif 'mshta' in det['image'].lower():
            if 'http://' in cmd and '198.51.100' in cmd:
                reasoning.append("❌ MALICIOUS: Mshta loading remote HTA from external IP")
                is_malicious = True
            elif 'enroll.corp' in cmd or 'corporate' in det['title'].lower():
                reasoning.append("✅ BENIGN: Corporate enrollment page (internal domain)")
                is_malicious = False
        
        elif 'bitsadmin' in det['image'].lower():
            if '/transfer' in cmd and 'http://' in cmd:
                reasoning.append("❌ MALICIOUS: Bitsadmin transferring binary from external source")
                is_malicious = True
            elif 'wuauserv' in str(det.get('process_tree', [])):
                reasoning.append("✅ BENIGN: Windows Update service using BITS")
                is_malicious = False
        
        elif 'rundll32' in det['image'].lower():
            if 'Control_RunDLL' in cmd and 'shell32.dll' in cmd:
                reasoning.append("✅ BENIGN: Standard Control Panel invocation")
                is_malicious = False
    
    # Check benign operations
    if is_malicious is None:
        if 'Backup' in det['category'] and 'backup.backupco.com' in det['command_line']:
            reasoning.append("✅ BENIGN: Legitimate enterprise backup to vendor cloud")
            is_malicious = False
        
        elif 'ProcDump' in det['title'] and 'w3wp.exe' in det['command_line']:
            reasoning.append("✅ BENIGN: ProcDump on IIS (w3wp), not LSASS")
            is_malicious = False
        
        elif 'MSBuild' in det['title'] and 'Dev pipeline' in det['title']:
            reasoning.append("✅ BENIGN: CI/CD build automation")
            is_malicious = False
        
        elif 'Driver update' in det['title'] and 'vendor-signed' in det['title']:
            reasoning.append("✅ BENIGN: Vendor-signed driver update")
            is_malicious = False
        
        elif 'Remote admin tool' in det['title'] and 'it.ops' == det['user']:
            reasoning.append("✅ BENIGN: IT admin tool pushing patches")
            is_malicious = False
    
    # Print reasoning
    for r in reasoning:
        print(f"  {r}")
    
    if not reasoning:
        print("  ⚠️ NO CLEAR INDICATORS - NEED DEEPER ANALYSIS")
        # Default to examining notes and context
        if 'legitimate' in det['notes'].lower() or 'expected' in det['notes'].lower():
            reasoning.append("✅ BENIGN: Notes indicate legitimate activity")
            is_malicious = False
        elif 'malicious' in det['notes'].lower() or 'proxy exec' in det['notes'].lower():
            reasoning.append("❌ MALICIOUS: Notes indicate malicious activity")
            is_malicious = True
    
    # Final verdict
    if is_malicious is None:
        verdict = "⚠️ UNCERTAIN - NEEDS MANUAL REVIEW"
        answer = "RTL{???}"
    elif is_malicious:
        verdict = "❌ TRUE POSITIVE (MALICIOUS)"
        answer = "RTL{TP}"
    else:
        verdict = "✅ FALSE POSITIVE (BENIGN)"
        answer = "RTL{FP}"
    
    print(f"\n🎯 VERDICT: {verdict}")
    print(f"📝 ANSWER: {answer}")
    
    results.append({
        'question_num': idx,
        'question': question,
        'detection_id': det['id'],
        'verdict': verdict,
        'answer': answer,
        'reasoning': reasoning
    })

# Summary
print("\n" + "=" * 80)
print("FINAL ANSWER KEY")
print("=" * 80)

tp_count = sum(1 for r in results if r['answer'] == 'RTL{TP}')
fp_count = sum(1 for r in results if r['answer'] == 'RTL{FP}')
uncertain = sum(1 for r in results if r['answer'] == 'RTL{???}')

print(f"\n📊 STATISTICS:")
print(f"  True Positives (Malicious): {tp_count}")
print(f"  False Positives (Benign): {fp_count}")
print(f"  Uncertain: {uncertain}")

print(f"\n📋 COPY-PASTE ANSWERS:")
print("-" * 80)
for r in results:
    status = "🔴" if r['answer'] == 'RTL{TP}' else "🟢" if r['answer'] == 'RTL{FP}' else "⚠️"
    print(f"{r['question_num']:2d}. {r['answer']} {status}")

# Save detailed report
with open('detailed_reanalysis.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n[✓] Detailed reanalysis saved to: detailed_reanalysis.json")
print("=" * 80)
