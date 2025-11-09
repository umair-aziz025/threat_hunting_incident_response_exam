#!/usr/bin/env python3
"""
CTHIRI Investigation - Answer Verification Script
Author: Umair Aziz
Date: November 9, 2025

Description:
This script verifies all exam answers against the extracted log data
and generates a final verification report.

Usage:
    python 03_verify_answers.py
"""

import json
import base64
from datetime import datetime

# Configuration
LOG_FILE = "../logs/all_logs_complete.json"

# Expected answers (for verification)
EXPECTED_ANSWERS = {
    "Q1_Golden_Ticket": {
        "event_id_in_logs": 76,
        "timestamp": "2025-08-18T01:15:00Z",
        "host": "DC01",
        "event_type": 4769,
        "client_ip": "10.10.5.23",
        "spn": "cifs/DC01"
    },
    "Q2_Silver_Ticket": {
        "event_id_in_logs": 221,
        "timestamp": "2025-08-18T03:40:00Z",
        "host": "WS02",
        "event_type": 4769
    },
    "Q3_LSASS_Dump": {
        "event_id_in_logs": 311,
        "timestamp": "2025-08-18T05:10:00Z",
        "host": "WS01",
        "user": "jdoe",
        "event_type": 10,
        "process": "procdump64.exe",
        "access_mask": "0x1FFFFF"
    },
    "Q4_PowerShell": {
        "event_id_in_logs": 421,
        "timestamp": "2025-08-18T07:00:00Z",
        "host": "WS02",
        "user": "msmith",
        "event_type": 4104,
        "url": "http://10.10.5.23/a.ps1",
        "script": "a.ps1"
    },
    "Q5A_Mimikatz": {
        "event_id_in_logs": 461,
        "timestamp": "2025-08-18T07:40:00Z",
        "host": "WS01",
        "user": "Administrator",
        "event_type": 1,
        "folder": "C:\\Windows\\Temp\\"
    },
    "Q5B_PsExec": {
        "event_id_in_logs": 396,
        "timestamp": "2025-08-18T06:35:00Z",
        "host": "FILE01",
        "account": "svc_backup",
        "event_type": 4688
    }
}

def print_banner():
    """Display script banner"""
    print("=" * 80)
    print("CTHIRI Investigation - Answer Verification Script")
    print("=" * 80)
    print()

def load_logs():
    """Load logs from JSON file"""
    print("[*] Loading logs for verification...")
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        print(f"[+] Loaded {len(logs)} events")
        return logs
    except Exception as e:
        print(f"[-] Error loading logs: {e}")
        return []

def verify_answer(logs, question, expected):
    """Verify a single answer against log data"""
    print(f"\n[*] Verifying {question}...")
    
    # Find the event
    event = None
    for log in logs:
        if log.get('id') == expected['event_id_in_logs']:
            event = log
            break
    
    if not event:
        print(f"    ✗ Event ID {expected['event_id_in_logs']} not found!")
        return False
    
    verified = True
    results = []
    
    # Verify each field
    for key, value in expected.items():
        if key == 'event_id_in_logs':
            continue
            
        if key == 'timestamp':
            if event.get('timestamp') == value:
                results.append(f"    ✓ Timestamp: {value}")
            else:
                results.append(f"    ✗ Timestamp: Expected {value}, got {event.get('timestamp')}")
                verified = False
                
        elif key == 'host':
            if event.get('host') == value:
                results.append(f"    ✓ Host: {value}")
            else:
                results.append(f"    ✗ Host: Expected {value}, got {event.get('host')}")
                verified = False
                
        elif key == 'user':
            if event.get('user') == value:
                results.append(f"    ✓ User: {value}")
            else:
                results.append(f"    ✗ User: Expected {value}, got {event.get('user')}")
                verified = False
                
        elif key == 'event_type':
            if event.get('event_id') == value:
                results.append(f"    ✓ Event ID: {value}")
            else:
                results.append(f"    ✗ Event ID: Expected {value}, got {event.get('event_id')}")
                verified = False
                
        elif key == 'client_ip':
            message = event.get('message', '')
            if value in message:
                results.append(f"    ✓ Client IP: {value}")
            else:
                results.append(f"    ⚠ Client IP: {value} (check message field)")
                
        elif key == 'spn':
            message = event.get('message', '')
            if value in message:
                results.append(f"    ✓ SPN: {value}")
            else:
                results.append(f"    ⚠ SPN: {value} (check message field)")
                
        elif key == 'process':
            image = event.get('image', '')
            if value in image:
                results.append(f"    ✓ Process: {value}")
            else:
                results.append(f"    ✗ Process: Expected {value}, got {image}")
                verified = False
                
        elif key == 'access_mask':
            message = event.get('message', '')
            if value in message:
                results.append(f"    ✓ AccessMask: {value}")
            else:
                results.append(f"    ⚠ AccessMask: {value} (check message field)")
                
        elif key == 'url':
            cmd = event.get('command_line', '')
            if 'EncodedCommand' in cmd:
                try:
                    parts = cmd.split('EncodedCommand')
                    if len(parts) > 1:
                        encoded = parts[1].strip().split()[0]
                        decoded = base64.b64decode(encoded).decode('utf-16-le')
                        if value in decoded:
                            results.append(f"    ✓ URL: {value}")
                        else:
                            results.append(f"    ✗ URL: Expected {value}, got different URL")
                            verified = False
                except:
                    results.append(f"    ⚠ URL: Could not decode")
                    
        elif key == 'script':
            results.append(f"    ✓ Script: {value}")
            
        elif key == 'folder':
            image = event.get('image', '')
            if value in image:
                results.append(f"    ✓ Folder: {value}")
            else:
                results.append(f"    ⚠ Folder: {value} (check image path)")
                
        elif key == 'account':
            user = event.get('user', '')
            if value in user or value == user:
                results.append(f"    ✓ Account: {value}")
            else:
                results.append(f"    ✗ Account: Expected {value}, got {user}")
                verified = False
    
    # Print results
    for result in results:
        print(result)
    
    if verified:
        print(f"    ✅ {question} - VERIFIED")
    else:
        print(f"    ❌ {question} - VERIFICATION FAILED")
    
    return verified

def verify_timeline(logs):
    """Verify timeline calculations"""
    print(f"\n[*] Verifying Timeline Calculations...")
    
    # Get events
    lsass = None
    psexec = None
    golden = None
    powershell = None
    
    for log in logs:
        if log.get('id') == 311:
            lsass = log
        elif log.get('id') == 396:
            psexec = log
        elif log.get('id') == 76:
            golden = log
        elif log.get('id') == 421:
            powershell = log
    
    verified = True
    
    # Check LSASS vs PsExec
    if lsass and psexec:
        lsass_time = datetime.fromisoformat(lsass['timestamp'].replace('Z', '+00:00'))
        psexec_time = datetime.fromisoformat(psexec['timestamp'].replace('Z', '+00:00'))
        
        if lsass_time < psexec_time:
            print(f"    ✓ LSASS dump ({lsass['timestamp']}) occurred before PsExec ({psexec['timestamp']})")
        else:
            print(f"    ✗ Timeline error: PsExec before LSASS")
            verified = False
    
    # Check time gap
    if golden and powershell:
        gt_time = datetime.fromisoformat(golden['timestamp'].replace('Z', '+00:00'))
        ps_time = datetime.fromisoformat(powershell['timestamp'].replace('Z', '+00:00'))
        time_diff = abs(ps_time - gt_time)
        
        hours = int(time_diff.total_seconds() // 3600)
        minutes = int((time_diff.total_seconds() % 3600) // 60)
        
        if hours == 5 and minutes == 45:
            print(f"    ✓ Time gap: {hours}h {minutes}m (matches expected: 5h 45m)")
        else:
            print(f"    ✗ Time gap: {hours}h {minutes}m (expected: 5h 45m)")
            verified = False
    
    # Check attacker IP
    attack_events = [log for log in logs if 'attack' in log.get('tags', [])]
    attacker_ip = "10.10.5.23"
    ip_found_count = 0
    
    for event in attack_events:
        if attacker_ip in event.get('message', ''):
            ip_found_count += 1
    
    if ip_found_count >= 2:
        print(f"    ✓ Attacker IP {attacker_ip} found in {ip_found_count} attack events")
    else:
        print(f"    ⚠ Attacker IP {attacker_ip} found in {ip_found_count} attack events")
    
    if verified:
        print(f"    ✅ Timeline - VERIFIED")
    else:
        print(f"    ❌ Timeline - VERIFICATION FAILED")
    
    return verified

def main():
    """Main execution function"""
    print_banner()
    
    # Load logs
    logs = load_logs()
    if not logs:
        return 1
    
    print("\n" + "=" * 80)
    print("VERIFYING ALL ANSWERS")
    print("=" * 80)
    
    # Verify each answer
    results = {}
    for question, expected in EXPECTED_ANSWERS.items():
        results[question] = verify_answer(logs, question, expected)
    
    # Verify timeline
    results['Timeline'] = verify_timeline(logs)
    
    # Summary
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    
    total = len(results)
    passed = sum(results.values())
    
    print(f"\nTotal Checks: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n✅ ALL ANSWERS VERIFIED SUCCESSFULLY!")
        print("🎉 Ready for exam submission!")
    else:
        print("\n⚠️  Some answers need review")
        print("Failed checks:")
        for question, result in results.items():
            if not result:
                print(f"  - {question}")
    
    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETE")
    print("=" * 80)
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    exit(main())
