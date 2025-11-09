#!/usr/bin/env python3
"""
CTHIRI Investigation - Log Extraction Script
Author: Umair Aziz
Date: November 9, 2025

Description:
This script extracts all security events from the IR Training Log Server
and saves them to a JSON file for analysis.

Usage:
    python 01_extract_logs.py
    
Prerequisites:
    - IR Log Server running on http://127.0.0.1:8080
    - Python requests library: pip install requests
"""

import requests
import json
from datetime import datetime

# Configuration
BASE_URL = "http://127.0.0.1:8080/api/logs"
OUTPUT_FILE = "../logs/all_logs_complete.json"
TOTAL_PAGES = 5  # Server has 5 pages of logs

def print_banner():
    """Display script banner"""
    print("=" * 80)
    print("CTHIRI Investigation - Log Extraction Script")
    print("=" * 80)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def extract_logs():
    """Extract all logs from the IR Training Log Server"""
    all_logs = []
    
    print(f"[*] Connecting to log server: {BASE_URL}")
    print(f"[*] Total pages to fetch: {TOTAL_PAGES}")
    print()
    
    for page in range(1, TOTAL_PAGES + 1):
        try:
            url = f"{BASE_URL}?page={page}"
            print(f"[+] Fetching page {page}/{TOTAL_PAGES}...", end=" ")
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logs = data.get('results', [])
                all_logs.extend(logs)
                print(f"✓ ({len(logs)} events)")
            else:
                print(f"✗ (HTTP {response.status_code})")
                
        except requests.exceptions.Timeout:
            print(f"✗ (Timeout)")
        except requests.exceptions.ConnectionError:
            print(f"✗ (Connection Error)")
        except Exception as e:
            print(f"✗ (Error: {e})")
    
    return all_logs

def save_logs(logs, filename):
    """Save logs to JSON file"""
    print()
    print(f"[*] Saving {len(logs)} events to {filename}...")
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
        print(f"[+] Successfully saved to {filename}")
        return True
    except Exception as e:
        print(f"[-] Error saving file: {e}")
        return False

def display_summary(logs):
    """Display summary statistics"""
    print()
    print("=" * 80)
    print("EXTRACTION SUMMARY")
    print("=" * 80)
    
    print(f"Total Events Extracted: {len(logs)}")
    
    # Count by source
    sources = {}
    for log in logs:
        source = log.get('source', 'Unknown')
        sources[source] = sources.get(source, 0) + 1
    
    print("\nEvents by Source:")
    for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
        print(f"  {source}: {count}")
    
    # Count by event ID
    event_ids = {}
    for log in logs:
        eid = log.get('event_id', 'Unknown')
        event_ids[eid] = event_ids.get(eid, 0) + 1
    
    print("\nTop Event IDs:")
    for eid, count in sorted(event_ids.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  Event {eid}: {count}")
    
    # Attack events
    attack_events = [log for log in logs if 'attack' in log.get('tags', [])]
    print(f"\nAttack-Tagged Events: {len(attack_events)}")
    
    if attack_events:
        print("\nAttack Events Details:")
        for event in attack_events:
            print(f"  ID {event['id']}: {event['timestamp']} | Event {event['event_id']} | {event['host']}")
            print(f"    {event.get('attack_category', 'N/A')}")
    
    print("=" * 80)

def main():
    """Main execution function"""
    print_banner()
    
    # Extract logs
    logs = extract_logs()
    
    if not logs:
        print("[-] No logs extracted. Please check the server connection.")
        return 1
    
    # Save logs
    if not save_logs(logs, OUTPUT_FILE):
        return 1
    
    # Display summary
    display_summary(logs)
    
    print()
    print(f"[+] Extraction complete at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[+] Logs are ready for analysis!")
    
    return 0

if __name__ == "__main__":
    exit(main())
