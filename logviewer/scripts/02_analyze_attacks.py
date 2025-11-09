#!/usr/bin/env python3
"""
CTHIRI Investigation - Attack Analysis Script
Author: Umair Aziz
Date: November 9, 2025

Description:
This script analyzes the extracted security logs to identify all attack events
and generates detailed findings for each question in the CTHIRI exam.

Usage:
    python 02_analyze_attacks.py
"""

import json
import base64
from datetime import datetime
from collections import defaultdict

# Configuration
LOG_FILE = "../logs/all_logs_complete.json"

def print_banner():
    """Display script banner"""
    print("=" * 80)
    print("CTHIRI Investigation - Attack Analysis Script")
    print("=" * 80)
    print()

def load_logs():
    """Load logs from JSON file"""
    print("[*] Loading logs from file...")
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        print(f"[+] Loaded {len(logs)} events")
        return logs
    except Exception as e:
        print(f"[-] Error loading logs: {e}")
        return []

def analyze_golden_ticket(logs):
    """Analyze and identify Golden Ticket attack"""
    print("\n" + "=" * 80)
    print("QUESTION 1: GOLDEN TICKET ATTACK")
    print("=" * 80)
    
    # Look for event ID 76 (the confirmed Golden Ticket event)
    golden_ticket = None
    for log in logs:
        if log.get('id') == 76:
            golden_ticket = log
            break
    
    if golden_ticket:
        print("\n[+] Golden Ticket Attack Found!")
        print(f"\n    Event ID: {golden_ticket['id']}")
        print(f"    Timestamp: {golden_ticket['timestamp']}")
        print(f"    Host: {golden_ticket['host']}")
        print(f"    Source: {golden_ticket['source']}")
        print(f"    Event Type: {golden_ticket['event_id']}")
        print(f"    Attack Category: {golden_ticket.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {golden_ticket.get('attack_technique', 'N/A')}")
        print(f"\n    Message: {golden_ticket['message']}")
        
        return golden_ticket
    else:
        print("[-] Golden Ticket event not found")
        return None

def analyze_silver_ticket(logs):
    """Analyze and identify Silver Ticket attack"""
    print("\n" + "=" * 80)
    print("QUESTION 2: SILVER TICKET ATTACK")
    print("=" * 80)
    
    # Look for event ID 221 (the confirmed Silver Ticket event)
    silver_ticket = None
    for log in logs:
        if log.get('id') == 221:
            silver_ticket = log
            break
    
    if silver_ticket:
        print("\n[+] Silver Ticket Attack Found!")
        print(f"\n    Event ID: {silver_ticket['id']}")
        print(f"    Timestamp: {silver_ticket['timestamp']}")
        print(f"    Host: {silver_ticket['host']}")
        print(f"    User: {silver_ticket.get('user', 'N/A')}")
        print(f"    Source: {silver_ticket['source']}")
        print(f"    Event Type: {silver_ticket['event_id']}")
        print(f"    Attack Category: {silver_ticket.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {silver_ticket.get('attack_technique', 'N/A')}")
        print(f"\n    Message: {silver_ticket['message']}")
        
        return silver_ticket
    else:
        print("[-] Silver Ticket event not found")
        return None

def analyze_lsass_dump(logs):
    """Analyze and identify LSASS dump"""
    print("\n" + "=" * 80)
    print("QUESTION 3: LSASS MEMORY DUMP")
    print("=" * 80)
    
    # Look for event ID 311 (the confirmed LSASS dump event)
    lsass_dump = None
    for log in logs:
        if log.get('id') == 311:
            lsass_dump = log
            break
    
    if lsass_dump:
        print("\n[+] LSASS Dump Found!")
        print(f"\n    Event ID: {lsass_dump['id']}")
        print(f"    Timestamp: {lsass_dump['timestamp']}")
        print(f"    Host: {lsass_dump['host']}")
        print(f"    User: {lsass_dump['user']}")
        print(f"    Process: {lsass_dump.get('image', 'N/A')}")
        print(f"    Target: {lsass_dump.get('target_process', 'N/A')}")
        print(f"    Event Type: {lsass_dump['event_id']}")
        print(f"    Command Line: {lsass_dump.get('command_line', 'N/A')}")
        print(f"    Attack Category: {lsass_dump.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {lsass_dump.get('attack_technique', 'N/A')}")
        print(f"\n    Message: {lsass_dump['message']}")
        
        return lsass_dump
    else:
        print("[-] LSASS dump event not found")
        return None

def analyze_powershell_encoded(logs):
    """Analyze and identify PowerShell encoded command"""
    print("\n" + "=" * 80)
    print("QUESTION 4: POWERSHELL ENCODEDCOMMAND")
    print("=" * 80)
    
    # Look for event ID 421 (the confirmed PowerShell event)
    ps_event = None
    for log in logs:
        if log.get('id') == 421:
            ps_event = log
            break
    
    if ps_event:
        print("\n[+] PowerShell EncodedCommand Found!")
        print(f"\n    Event ID: {ps_event['id']}")
        print(f"    Timestamp: {ps_event['timestamp']}")
        print(f"    Host: {ps_event['host']}")
        print(f"    User: {ps_event['user']}")
        print(f"    Event Type: {ps_event['event_id']}")
        print(f"    Attack Category: {ps_event.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {ps_event.get('attack_technique', 'N/A')}")
        
        # Extract and decode base64
        cmd_line = ps_event.get('command_line', '')
        if 'EncodedCommand' in cmd_line:
            # Extract base64 part
            parts = cmd_line.split('EncodedCommand')
            if len(parts) > 1:
                encoded = parts[1].strip().split()[0]
                try:
                    decoded = base64.b64decode(encoded).decode('utf-16-le')
                    print(f"\n    Encoded Command (base64): {encoded[:50]}...")
                    print(f"    Decoded Command: {decoded}")
                    
                    # Extract URL
                    if 'http' in decoded:
                        import re
                        urls = re.findall(r'http[s]?://[^\s\'"]+', decoded)
                        if urls:
                            print(f"    Malicious URL: {urls[0]}")
                            # Extract script name
                            script_name = urls[0].split('/')[-1]
                            print(f"    Script Name: {script_name}")
                except Exception as e:
                    print(f"    Decoding error: {e}")
        
        print(f"\n    Message: {ps_event['message']}")
        return ps_event
    else:
        print("[-] PowerShell encoded event not found")
        return None

def analyze_mimikatz(logs):
    """Analyze and identify Mimikatz execution"""
    print("\n" + "=" * 80)
    print("QUESTION 5A: MIMIKATZ EXECUTION")
    print("=" * 80)
    
    # Look for event ID 461 (the confirmed Mimikatz event)
    mimikatz = None
    for log in logs:
        if log.get('id') == 461:
            mimikatz = log
            break
    
    if mimikatz:
        print("\n[+] Mimikatz Execution Found!")
        print(f"\n    Event ID: {mimikatz['id']}")
        print(f"    Timestamp: {mimikatz['timestamp']}")
        print(f"    Host: {mimikatz['host']}")
        print(f"    User: {mimikatz['user']}")
        print(f"    Image: {mimikatz.get('image', 'N/A')}")
        print(f"    Command Line: {mimikatz.get('command_line', 'N/A')}")
        print(f"    Event Type: {mimikatz['event_id']}")
        print(f"    Attack Category: {mimikatz.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {mimikatz.get('attack_technique', 'N/A')}")
        
        # Extract folder path
        image_path = mimikatz.get('image', '')
        if image_path:
            folder = '\\'.join(image_path.split('\\')[:-1]) + '\\'
            print(f"    Folder Path: {folder}")
        
        print(f"\n    Message: {mimikatz['message']}")
        return mimikatz
    else:
        print("[-] Mimikatz event not found")
        return None

def analyze_psexec(logs):
    """Analyze and identify PsExec lateral movement"""
    print("\n" + "=" * 80)
    print("QUESTION 5B: PSEXEC LATERAL MOVEMENT")
    print("=" * 80)
    
    # Look for event ID 396 (the confirmed PsExec event)
    psexec = None
    for log in logs:
        if log.get('id') == 396:
            psexec = log
            break
    
    if psexec:
        print("\n[+] PsExec Lateral Movement Found!")
        print(f"\n    Event ID: {psexec['id']}")
        print(f"    Timestamp: {psexec['timestamp']}")
        print(f"    Remote Host: {psexec['host']}")
        print(f"    Account: {psexec.get('user', 'N/A')}")
        print(f"    Source: {psexec['source']}")
        print(f"    Event Type: {psexec['event_id']}")
        print(f"    Image: {psexec.get('image', 'N/A')}")
        print(f"    Command Line: {psexec.get('command_line', 'N/A')}")
        print(f"    Attack Category: {psexec.get('attack_category', 'N/A')}")
        print(f"    MITRE Technique: {psexec.get('attack_technique', 'N/A')}")
        
        # Extract source host from command line
        cmd = psexec.get('command_line', '')
        if '\\\\' in cmd:
            import re
            match = re.search(r'\\\\(\w+)', cmd)
            if match:
                print(f"    Source Host: {match.group(1)}")
        
        print(f"\n    Message: {psexec['message']}")
        print(f"\n    Filter Query: event:{psexec['event_id']} source:{psexec['source']}")
        
        return psexec
    else:
        print("[-] PsExec event not found")
        return None

def analyze_timeline(logs, events):
    """Analyze timeline and chronology"""
    print("\n" + "=" * 80)
    print("QUESTION 5C: TIMELINE & CHRONOLOGY")
    print("=" * 80)
    
    # Sort attack events by timestamp
    attack_events = []
    for event in events.values():
        if event:
            attack_events.append(event)
    
    attack_events.sort(key=lambda x: x['timestamp'])
    
    print("\n[+] Complete Attack Timeline:")
    print()
    for i, event in enumerate(attack_events, 1):
        time = event['timestamp'].split('T')[1].replace('Z', '')
        print(f"    {i}. {time} | {event.get('attack_category', 'Event')} | {event['host']}")
    
    # Find LSASS and PsExec
    lsass = events.get('lsass')
    psexec = events.get('psexec')
    
    if lsass and psexec:
        lsass_time = datetime.fromisoformat(lsass['timestamp'].replace('Z', '+00:00'))
        psexec_time = datetime.fromisoformat(psexec['timestamp'].replace('Z', '+00:00'))
        
        print(f"\n[+] Sequence Analysis:")
        print(f"    LSASS Dump: {lsass['timestamp']}")
        print(f"    PsExec:     {psexec['timestamp']}")
        
        if lsass_time < psexec_time:
            gap = psexec_time - lsass_time
            print(f"    Result: LSASS dump occurred FIRST (by {gap})")
        else:
            print(f"    Result: PsExec occurred FIRST")
    
    # Calculate time gap between Golden Ticket and PowerShell
    golden = events.get('golden_ticket')
    powershell = events.get('powershell')
    
    if golden and powershell:
        gt_time = datetime.fromisoformat(golden['timestamp'].replace('Z', '+00:00'))
        ps_time = datetime.fromisoformat(powershell['timestamp'].replace('Z', '+00:00'))
        time_diff = abs(ps_time - gt_time)
        
        hours = int(time_diff.total_seconds() // 3600)
        minutes = int((time_diff.total_seconds() % 3600) // 60)
        
        print(f"\n[+] Time Gap Analysis:")
        print(f"    Golden Ticket: {golden['timestamp']}")
        print(f"    PowerShell:    {powershell['timestamp']}")
        print(f"    Time Gap:      {hours}h {minutes}m")
    
    # Find suspicious 4769 events and client IPs
    suspicious_4769 = [log for log in logs if log.get('event_id') == 4769 and 
                       log.get('level') in ['Error', 'Warning'] and 
                       'attack' in log.get('tags', [])]
    
    print(f"\n[+] Suspicious 4769 Events: {len(suspicious_4769)}")
    
    client_ips = set()
    accounts = set()
    for event in suspicious_4769:
        print(f"    Event {event['id']}: {event['timestamp']} | {event['host']} | {event.get('user', 'N/A')}")
        
        # Try to find client IP in message
        message = event.get('message', '')
        if '10.10' in message:
            import re
            ips = re.findall(r'10\.10\.\d+\.\d+', message)
            client_ips.update(ips)
        
        accounts.add(event.get('user', 'N/A'))
    
    if client_ips:
        print(f"\n[+] Client IPs in suspicious 4769 events:")
        for ip in client_ips:
            print(f"    - {ip}")
    
    print(f"\n[+] Accounts implicated:")
    for account in accounts:
        print(f"    - {account}")

def main():
    """Main execution function"""
    print_banner()
    
    # Load logs
    logs = load_logs()
    if not logs:
        return 1
    
    # Analyze each attack type
    events = {}
    events['golden_ticket'] = analyze_golden_ticket(logs)
    events['silver_ticket'] = analyze_silver_ticket(logs)
    events['lsass'] = analyze_lsass_dump(logs)
    events['powershell'] = analyze_powershell_encoded(logs)
    events['mimikatz'] = analyze_mimikatz(logs)
    events['psexec'] = analyze_psexec(logs)
    
    # Analyze timeline
    analyze_timeline(logs, events)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print("\n[+] All attack events identified and analyzed!")
    print("[+] Ready for final verification and report generation.")
    
    return 0

if __name__ == "__main__":
    exit(main())
