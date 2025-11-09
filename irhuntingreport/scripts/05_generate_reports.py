"""
IR Hunting Report Builder - Report Generation Script
Generates comprehensive incident response reports for all 5 cases
Submits reports to the API and captures flags
"""

import json
import requests

API_BASE = "http://127.0.0.1:8080"

def extract_timestamp(logs):
    """Extract earliest timestamp from logs"""
    for log in logs:
        if log.startswith('20'):
            return log.split()[0]
    return "2025-07-21T00:00:00Z"

def generate_case1_report(case):
    """
    Case 1: DNS Exfiltration via TXT Records
    - PowerShell script exfiltrating data via DNS TXT queries with base64 encoding
    """
    report = {
        "scenario_id": case['id'],
        "title": "DNS Exfiltration via TXT Records",
        "timestamp": "2025-07-21T14:03:12Z",
        "description": """Detected data exfiltration through DNS TXT record queries. User 'jdoe' on host ENG-03 executed a PowerShell script spawned by explorer.exe that read a local file (quotes.xlsx) and exfiltrated it via DNS. The script allocated approximately 64KB of data and generated over 200 DNS TXT requests in a burst pattern to exfil.attacker.com using base64-encoded query names. The PowerShell command used hidden window mode (-w hidden) and no-profile (-nop) flags to evade detection.""",
        "mitre": ["T1071.004", "T1132", "T1041", "T1027", "T1568", "T1005"],
        "impacted_hosts": ["ENG-03"],
        "impacted_accounts": ["jdoe"],
        "iocs": ["exfil.attacker.com", "8.8.8.8", "TXT"],
        "containment": "Isolate host ENG-03 from network immediately. Block domain exfil.attacker.com at DNS firewall and sinkhole malicious DNS queries. EDR block on suspicious PowerShell DNS beaconing patterns. Quarantine affected user jdoe pending investigation.",
        "eradication": "Remove malicious PowerShell script from C:\\Users\\jdoe\\Desktop\\. Clean PowerShell profile and command history. Delete artifact files and disable any scheduled task persistence. Terminate suspicious processes and clear DNS cache.",
        "recovery": "Monitor DNS traffic for anomalous TXT queries and beaconing patterns. Restore network access with enhanced DNS logging. User awareness training for jdoe on phishing and social engineering. MFA enforcement for sensitive accounts. Review access logs for lateral movement."
    }
    return report

def generate_case2_report(case):
    """
    Case 2: ICMP Exfiltration via Large Ping Payloads
    """
    report = {
        "scenario_id": case['id'],
        "title": "ICMP-based Data Exfiltration",
        "timestamp": "2025-07-22T09:18:41Z",
        "description": """Identified data exfiltration via ICMP echo requests with unusually large payloads. User 'msmith' on workstation WS-07 executed a command-line ping operation targeting external IP 203.0.113.45 with 1400-byte payloads over 60 iterations. This technique leverages ICMP protocol, which is often permitted through firewalls, to covertly exfiltrate data by embedding it in ping packet payloads. EDR telemetry confirmed sustained ICMP traffic with abnormal payload sizes.""",
        "mitre": ["T1048", "T1095", "T1041", "T1027"],
        "impacted_hosts": ["WS-07"],
        "impacted_accounts": ["msmith"],
        "iocs": ["203.0.113.45", "ping -l 1400"],
        "containment": "Isolate WS-07 from network immediately. Block ICMP traffic to external IP 203.0.113.45 at perimeter firewall. Suspended msmith's account pending forensic analysis. Implemented temporary ICMP egress filtering for all workstations.",
        "eradication": "Remove malicious batch script or tool used for ICMP exfiltration. Policy update to restrict ICMP payload sizes to maximum 64 bytes. Script cleanup to remove command history and artifacts. Conducted memory forensics to identify exfiltrated data.",
        "recovery": "Monitor ICMP traffic for abnormal payload sizes and sustained connections. Baseline traffic patterns to detect future anomalies. User awareness training for msmith on data handling policies. Restored msmith account after security verification."
    }
    return report

def generate_case3_report(case):
    """
    Case 3: HTTPS Exfiltration to Unapproved External Endpoint
    """
    report = {
        "scenario_id": case['id'],
        "title": "HTTPS Data Exfiltration (Unapproved Endpoint)",
        "timestamp": "2025-07-24T22:47:02Z",
        "description": """Detected large-scale data exfiltration over HTTPS to an unapproved external endpoint. User 'analyst' on finance workstation FIN-11 executed a Python script (upload.py) that uploaded a 12.8MB file (Q3.zip) from the Finance Ledger directory to cdn-drop.example via HTTPS POST. The proxy logs show the connection used TLS with SNI to an external IP (198.51.100.120) not approved in corporate policies. The user-agent string 'python-requests/2.31' indicates automated scripted upload rather than browser-based activity.""",
        "mitre": ["T1041", "T1071.001", "T1560", "T1027"],
        "impacted_hosts": ["FIN-11"],
        "impacted_accounts": ["analyst"],
        "iocs": ["cdn-drop.example", "198.51.100.120"],
        "containment": "Block SNI cdn-drop.example and IP 198.51.100.120 at proxy and firewall. Isolate FIN-11 from network immediately. Revoke creds for analyst account pending investigation. Proxy policy enforcement to whitelist approved upload destinations.",
        "eradication": "Remove tool upload.py from C:\\Tools\\ directory. Delete script and related artifacts. Clear persistence mechanisms from startup folders and registry. Quarantined Q3.zip file for legal preservation and forensic analysis.",
        "recovery": "Rotate passwords for all finance team accounts including analyst. Data loss assessment to determine Q3.zip contents and breach impact. Monitor TLS connections to external endpoints with DLP enforcement. Enhanced application whitelisting on finance workstations."
    }
    return report

def generate_case4_report(case):
    """
    Case 4: HTTP C2 Beacon with Command Tasking
    """
    report = {
        "scenario_id": case['id'],
        "title": "HTTP C2 Beacon with Tasking & Results",
        "timestamp": "2025-07-26T03:04:11Z",
        "description": """Identified command-and-control (C2) activity using HTTP beaconing. Host WS-19 initiated periodic HTTP GET requests to 203.0.113.99 every 60 seconds, requesting tasks from /beacon and /task endpoints. The C2 server responded with commands including 'whoami && ipconfig', which were executed by cmd.exe under user 'jdoe'. Results (4KB) were subsequently exfiltrated back to the C2 server via POST to /result endpoint. EDR detected that beacon.exe was spawned by a scheduled task, indicating persistence mechanism.""",
        "mitre": ["T1071.001", "T1059.003", "T1053", "T1105"],
        "impacted_hosts": ["WS-19"],
        "impacted_accounts": ["jdoe"],
        "iocs": ["203.0.113.99", "/beacon", "/task"],
        "containment": "Isolate WS-19 from network immediately. Block egress traffic to C2 server 203.0.113.99 at firewall and proxy. Sinkhole malicious domain if DNS-based. EDR block on beacon.exe process and associated scheduled task.",
        "eradication": "Remove scheduled task used for beacon.exe persistence. Delete persistence mechanisms from registry Run keys and startup folders. Wipe beacon.exe malware from disk and memory. Conducted full malware scan and artifact removal.",
        "recovery": "Hardening WS-19 with application whitelisting and execution policies. Monitor HTTP traffic for periodic beaconing patterns. User reset for jdoe account with new credentials and MFA enforcement. Deployed behavioral analytics to detect C2 communication patterns."
    }
    return report

def generate_case5_report(case):
    """
    Case 5: HTTPS C2 with Encrypted Communications and PowerShell
    """
    report = {
        "scenario_id": case['id'],
        "title": "Encrypted C2 over HTTPS with PowerShell",
        "timestamp": "2025-07-28T16:35:20Z",
        "description": """Detected encrypted command-and-control communications over HTTPS with PowerShell execution. Host LAP-DEV01 established TLS connections to cdn-c2.example (198.51.100.200) with distinct JA3 fingerprint (769,4865,4867) indicating non-standard TLS client. The connection involved POST requests to /b endpoint (1.2KB payloads) masquerading as Chrome browser traffic. EDR telemetry revealed child PowerShell process executing encoded commands (-enc flag) that were decoded to 'Invoke-Command dir C:\', indicating remote command execution capability. User 'dev.build' was the execution context.""",
        "mitre": ["T1071.001", "T1059.001", "T1573", "T1140", "T1001"],
        "impacted_hosts": ["LAP-DEV01"],
        "impacted_accounts": ["dev.build"],
        "iocs": ["cdn-c2.example", "198.51.100.200", "JA3"],
        "containment": "Isolate LAP-DEV01 from network immediately. Cert pinning enforcement to detect non-standard TLS clients. TLS block for cdn-c2.example and IP 198.51.100.200. EDR block on PowerShell encoded command execution and suspicious JA3 fingerprints.",
        "eradication": "Remove persistence mechanisms from registry and startup locations. Delete script files and encoded PowerShell commands. Clean registry Run keys and scheduled tasks. Removed malware beacon binary and cleared TLS session artifacts.",
        "recovery": "Reset tokens and credentials for dev.build account with MFA enforcement. Monitor TLS traffic for abnormal JA3 fingerprints and encrypted C2 patterns. Hunt similar JA3 signatures across environment. Deployed PowerShell Constrained Language Mode and script block logging."
    }
    return report

def submit_report(report):
    """Submit a report to the API and return the flag"""
    try:
        response = requests.post(
            f"{API_BASE}/api/submit",
            json=report,
            headers={"Content-Type": "application/json"}
        )
        result = response.json()
        return result
    except Exception as e:
        return {"ok": False, "errors": [str(e)]}

def main():
    print("="*80)
    print("IR HUNTING REPORT BUILDER - REPORT GENERATION & SUBMISSION")
    print("="*80)
    
    # Load scenarios
    with open('ir_scenarios.json', 'r') as f:
        scenarios = json.load(f)
    
    print(f"\n✅ Loaded {len(scenarios)} scenarios\n")
    
    # Report generators mapping
    generators = {
        1: generate_case1_report,
        2: generate_case2_report,
        3: generate_case3_report,
        4: generate_case4_report,
        5: generate_case5_report
    }
    
    flags_captured = {}
    
    # Process each case
    for case in scenarios:
        case_id = case['id']
        case_code = case['code']
        case_title = case['title']
        
        print(f"\n{'='*80}")
        print(f"PROCESSING CASE {case_id}: {case_code}")
        print(f"{'='*80}")
        print(f"Title: {case_title}")
        
        # Generate report
        if case_id in generators:
            print(f"\n📝 Generating incident report...")
            report = generators[case_id](case)
            
            # Display report summary
            print(f"\n✅ Report Generated:")
            print(f"   Title: {report['title']}")
            print(f"   Timestamp: {report['timestamp']}")
            print(f"   MITRE Techniques: {', '.join(report['mitre'])}")
            print(f"   Impacted Hosts: {', '.join(report['impacted_hosts'])}")
            print(f"   Impacted Accounts: {', '.join(report['impacted_accounts'])}")
            print(f"   IOCs: {', '.join(report['iocs'])}")
            print(f"   Description Length: {len(report['description'])} chars")
            print(f"   Containment Length: {len(report['containment'])} chars")
            print(f"   Eradication Length: {len(report['eradication'])} chars")
            print(f"   Recovery Length: {len(report['recovery'])} chars")
            
            # Submit report
            print(f"\n🚀 Submitting report to API...")
            result = submit_report(report)
            
            if result.get('ok'):
                flag = result.get('flag', 'NO_FLAG')
                flags_captured[case_code] = flag
                print(f"✅ SUCCESS! Flag captured: {flag}")
            else:
                errors = result.get('errors', ['Unknown error'])
                print(f"❌ FAILED! Errors:")
                for error in errors:
                    print(f"   • {error}")
        else:
            print(f"⚠️  No generator found for case {case_id}")
    
    # Final summary
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"Total Cases: {len(scenarios)}")
    print(f"Flags Captured: {len(flags_captured)}/{len(scenarios)}")
    
    if flags_captured:
        print(f"\n🏆 FLAGS CAPTURED:")
        for code, flag in flags_captured.items():
            print(f"   {code}: {flag}")
    
    # Save flags to file
    with open('ir_flags.json', 'w') as f:
        json.dump(flags_captured, f, indent=2)
    
    print(f"\n✅ Flags saved to ir_flags.json")
    print(f"\n{'='*80}")
    
    if len(flags_captured) == len(scenarios):
        print("🎉 ALL CHALLENGES COMPLETED SUCCESSFULLY!")
    else:
        print("⚠️  Some challenges need review - check errors above")
    
    print(f"{'='*80}")

if __name__ == '__main__':
    main()
