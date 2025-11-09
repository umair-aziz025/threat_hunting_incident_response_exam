import json
import base64
from datetime import datetime

print("=" * 80)
print("ANSWERING EXAM QUESTIONS - DATA EXFILTRATION & C2")
print("=" * 80)

# Load logs
with open('all_network_logs.json', 'r') as f:
    all_logs = json.load(f)

answers = {}

# ============================================================================
# DNS EXFILTRATION QUESTIONS
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 1: DNS EXFILTRATION")
print("=" * 80)

# Find DNS exfiltration logs
dns_exfil_logs = [log for log in all_logs 
                  if log.get('app') == 'DNS' and 'exfil.attacker.net' in log.get('dns_qname', '')]

print(f"\n[*] Found {len(dns_exfil_logs)} DNS exfiltration queries")

if dns_exfil_logs:
    # Q1: DNS exfil source host?
    src_ips = set([log.get('src_ip') for log in dns_exfil_logs])
    answers['dns_exfil_source_host'] = list(src_ips)[0] if src_ips else "Not found"
    print(f"\nQ1: DNS exfil source host?")
    print(f"    Answer: {answers['dns_exfil_source_host']}")
    
    # Q2: DNS exfil base domain?
    # Extract base domain from exfil queries
    base_domain = "exfil.attacker.net"  # From the queries we saw
    answers['dns_exfil_base_domain'] = base_domain
    print(f"\nQ2: DNS exfil base domain?")
    print(f"    Answer: {answers['dns_exfil_base_domain']}")
    
    # Q3: DNS exfil query types used?
    qtypes = set([log.get('dns_qtype') for log in dns_exfil_logs])
    answers['dns_exfil_query_types'] = ', '.join(sorted(qtypes))
    print(f"\nQ3: DNS exfil query types used?")
    print(f"    Answer: {answers['dns_exfil_query_types']}")
    
    # Q4: DNS exfil destination (resolver) IP?
    dst_ips = set([log.get('dst_ip') for log in dns_exfil_logs])
    answers['dns_exfil_destination_ip'] = list(dst_ips)[0] if dst_ips else "Not found"
    print(f"\nQ4: DNS exfil destination (resolver) IP?")
    print(f"    Answer: {answers['dns_exfil_destination_ip']}")
    
    # Show sample queries
    print(f"\n[*] Sample DNS Exfiltration Queries:")
    for log in dns_exfil_logs[:3]:
        print(f"    - {log.get('dns_qname')} ({log.get('dns_qtype')}) at {log.get('timestamp')}")

# Q5: What is HOST/DNS/SNI with the largest data exfiltration size?
print(f"\n\nQ5: What is HOST/DNS/SNI with the largest data exfiltration size?")

# Calculate total sizes by host/domain/SNI
from collections import defaultdict

host_sizes = defaultdict(int)

# DNS
for log in all_logs:
    if log.get('app') == 'DNS':
        qname = log.get('dns_qname', '')
        size = log.get('size', 0)
        if qname:
            host_sizes[qname] += size

# HTTP
for log in all_logs:
    if log.get('app') == 'HTTP':
        host = log.get('host', '')
        size = log.get('size', 0)
        if host:
            host_sizes[host] += size

# HTTPS
for log in all_logs:
    if log.get('app') == 'HTTPS':
        sni = log.get('sni') or log.get('host', '')
        size = log.get('size', 0)
        if sni:
            host_sizes[sni] += size

# Find largest
largest_host = max(host_sizes.items(), key=lambda x: x[1])
answers['largest_exfil_host'] = f"{largest_host[0]} ({largest_host[1]} bytes)"
print(f"    Answer: {largest_host[0]}")
print(f"    Size: {largest_host[1]} bytes")

# ============================================================================
# ICMP EXFILTRATION QUESTIONS
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 2: ICMP EXFILTRATION")
print("=" * 80)

# Find suspicious ICMP traffic (large payloads)
icmp_logs = [log for log in all_logs if log.get('app') == 'ICMP']
suspicious_icmp = [log for log in icmp_logs if log.get('size', 0) > 100]

print(f"\n[*] Found {len(suspicious_icmp)} suspicious ICMP packets (size > 100 bytes)")

if suspicious_icmp:
    # Q6: ICMP exfil source?
    src_ips = set([log.get('src_ip') for log in suspicious_icmp])
    answers['icmp_exfil_source'] = list(src_ips)[0] if len(src_ips) == 1 else ', '.join(src_ips)
    print(f"\nQ6: ICMP exfil source?")
    print(f"    Answer: {answers['icmp_exfil_source']}")
    
    # Q7: ICMP exfil destination?
    dst_ips = set([log.get('dst_ip') for log in suspicious_icmp])
    answers['icmp_exfil_destination'] = list(dst_ips)[0] if len(dst_ips) == 1 else ', '.join(dst_ips)
    print(f"\nQ7: ICMP exfil destination?")
    print(f"    Answer: {answers['icmp_exfil_destination']}")
    
    # Q8: ICMP exfil type request?
    icmp_types = set([log.get('icmp_type') for log in suspicious_icmp])
    answers['icmp_exfil_type'] = list(icmp_types)[0] if len(icmp_types) == 1 else ', '.join(icmp_types)
    print(f"\nQ8: ICMP exfil type request?")
    print(f"    Answer: {answers['icmp_exfil_type']}")
    
    # Q9: What type of encode is being used to exfiltrate data via ICMP?
    sample_payload = suspicious_icmp[0].get('payload', '')
    print(f"\nQ9: What type of encode is being used to exfiltrate data via ICMP?")
    print(f"    Sample payload: {sample_payload[:100]}...")
    
    # Check encoding type
    encoding_type = "Unknown"
    if sample_payload:
        # Check if Base64
        try:
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in sample_payload):
                # Try to decode
                decoded = base64.b64decode(sample_payload)
                encoding_type = "Base64"
                print(f"    [*] Successfully decoded as Base64")
                print(f"    [*] Decoded sample: {decoded[:50]}")
        except:
            pass
        
        # Check if Hex
        if encoding_type == "Unknown":
            try:
                if all(c in '0123456789abcdefABCDEF' for c in sample_payload):
                    encoding_type = "Hexadecimal"
            except:
                pass
    
    answers['icmp_encoding_type'] = encoding_type
    print(f"    Answer: {encoding_type}")

# ============================================================================
# HTTPS EXFILTRATION QUESTIONS
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 3: HTTPS EXFILTRATION")
print("=" * 80)

# Find largest HTTPS transfer
https_logs = [log for log in all_logs if log.get('app') == 'HTTPS']
largest_https = max(https_logs, key=lambda x: x.get('size', 0))

print(f"\n[*] Found largest HTTPS transfer:")
print(f"    Log ID: {largest_https.get('id')}")
print(f"    Timestamp: {largest_https.get('timestamp')}")

# Q10: HTTPS exfil request method?
answers['https_exfil_method'] = largest_https.get('method', 'Unknown')
print(f"\nQ10: HTTPS exfil request method?")
print(f"    Answer: {answers['https_exfil_method']}")

# Q11: HTTPS exfil URI?
answers['https_exfil_uri'] = largest_https.get('uri', 'Unknown')
print(f"\nQ11: HTTPS exfil URI?")
print(f"    Answer: {answers['https_exfil_uri']}")

# Q12: HTTPS exfil data size bytes?
answers['https_exfil_size'] = largest_https.get('size', 0)
print(f"\nQ12: HTTPS exfil data size bytes?")
print(f"    Answer: {answers['https_exfil_size']} bytes")

# Q13: HTTPS exfil domain or host?
answers['https_exfil_host'] = largest_https.get('sni') or largest_https.get('host', 'Unknown')
print(f"\nQ13: HTTPS exfil domain or host?")
print(f"    Answer: {answers['https_exfil_host']}")

# Q14: Create filter for exfil.attacker.net
print(f"\n\nQ14: Create a filter for exfil.attacker.net domain")
if dns_exfil_logs:
    sample_log = dns_exfil_logs[0]
    filter_query = f"app:DNS qtype:{sample_log.get('dns_qtype')} qname:exfil.attacker.net"
    answers['dns_exfil_filter'] = filter_query
    print(f"    Answer: {filter_query}")

# ============================================================================
# C2 DETECTION QUESTIONS
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 4: C2 (COMMAND & CONTROL) DETECTION")
print("=" * 80)

# Find C2 traffic - look for beaconing patterns with /api/ endpoints
http_logs = [log for log in all_logs if log.get('app') == 'HTTP']
c2_candidates = [log for log in http_logs 
                 if '/api/' in log.get('uri', '') or 'beacon' in log.get('uri', '')]

print(f"\n[*] Found {len(c2_candidates)} potential C2 HTTP requests")

if c2_candidates:
    # Group by host
    from collections import Counter
    c2_hosts = Counter([log.get('host') for log in c2_candidates])
    
    print(f"\n[*] Potential C2 hosts:")
    for host, count in c2_hosts.most_common():
        print(f"    {host}: {count} requests")
    
    # Most likely C2 host (with /api/ endpoints)
    c2_host = c2_hosts.most_common(1)[0][0]
    c2_logs = [log for log in c2_candidates if log.get('host') == c2_host]
    
    # Q15: C2 over protocol?
    answers['c2_protocol'] = "HTTP"  # We found it in HTTP traffic
    print(f"\nQ15: C2 over protocol?")
    print(f"    Answer: {answers['c2_protocol']}")
    
    # Q16: C2 over HTTP source IP?
    src_ips = set([log.get('src_ip') for log in c2_logs])
    answers['c2_http_source_ip'] = list(src_ips)[0] if len(src_ips) == 1 else ', '.join(src_ips)
    print(f"\nQ16: C2 over HTTP source IP?")
    print(f"    Answer: {answers['c2_http_source_ip']}")
    
    # Q17: C2 over HTTP destination IP?
    dst_ips = set([log.get('dst_ip') for log in c2_logs])
    answers['c2_http_destination_ip'] = list(dst_ips)[0] if len(dst_ips) == 1 else ', '.join(dst_ips)
    print(f"\nQ17: C2 over HTTP destination IP?")
    print(f"    Answer: {answers['c2_http_destination_ip']}")
    
    # Q18: C2 over HTTP Host?
    answers['c2_http_host'] = c2_host
    print(f"\nQ18: C2 over HTTP Host?")
    print(f"    Answer: {answers['c2_http_host']}")
    
    # Q19: What command did HTTP C2 execute at 04:30:10Z?
    cmd_log = [log for log in c2_logs if '04:30:10' in log.get('timestamp', '')]
    if cmd_log:
        payload = cmd_log[0].get('payload', '')
        print(f"\nQ19: What command did HTTP C2 execute at 04:30:10Z?")
        print(f"    Encoded payload: {payload}")
        
        # Try to decode Base64
        try:
            decoded = base64.b64decode(payload).decode('utf-8')
            answers['c2_command_04_30_10'] = decoded
            print(f"    Decoded command: {decoded}")
            print(f"    Answer: {decoded}")
        except:
            answers['c2_command_04_30_10'] = payload
            print(f"    Answer: {payload}")
    
    # Q20: C2 HTTP user-agent string used?
    user_agents = set([log.get('ua', '') for log in c2_logs if log.get('ua')])
    answers['c2_http_user_agent'] = list(user_agents)[0] if user_agents else "Unknown"
    print(f"\nQ20: C2 HTTP user-agent string used?")
    print(f"    Answer: {answers['c2_http_user_agent']}")
    
    # Q23: Write at least one of the endpoints used by c2?
    endpoints = set([log.get('uri', '') for log in c2_logs if log.get('uri')])
    answers['c2_endpoints'] = ', '.join(endpoints)
    print(f"\nQ23: Write at least one of the endpoints used by c2?")
    print(f"    Answer: {', '.join(endpoints)}")

# HTTPS C2
https_c2_candidates = [log for log in https_logs 
                       if '/v1/' in log.get('uri', '') or 'checkin' in log.get('uri', '') 
                       or 'tasks' in log.get('uri', '') or 'results' in log.get('uri', '')]

print(f"\n[*] Found {len(https_c2_candidates)} potential C2 HTTPS requests")

if https_c2_candidates:
    # Q21: C2 over HTTPS source IP?
    src_ips = set([log.get('src_ip') for log in https_c2_candidates])
    answers['c2_https_source_ip'] = list(src_ips)[0] if len(src_ips) == 1 else ', '.join(src_ips)
    print(f"\nQ21: C2 over HTTPS source IP?")
    print(f"    Answer: {answers['c2_https_source_ip']}")
    
    # Q22: C2 over HTTPS SNI?
    snis = set([log.get('sni') or log.get('host', '') for log in https_c2_candidates])
    answers['c2_https_sni'] = list(snis)[0] if len(snis) == 1 else ', '.join(snis)
    print(f"\nQ22: C2 over HTTPS SNI?")
    print(f"    Answer: {answers['c2_https_sni']}")
    
    # Q23: C2 over HTTPS destination IP?
    dst_ips = set([log.get('dst_ip') for log in https_c2_candidates])
    answers['c2_https_destination_ip'] = list(dst_ips)[0] if len(dst_ips) == 1 else ', '.join(dst_ips)
    print(f"\nQ23: C2 over HTTPS destination IP?")
    print(f"    Answer: {answers['c2_https_destination_ip']}")

# ============================================================================
# SAVE ANSWERS
# ============================================================================
print("\n" + "=" * 80)
print("SAVING ANSWERS")
print("=" * 80)

with open('answers.json', 'w') as f:
    json.dump(answers, f, indent=2)

print(f"\n[✓] All answers saved to: answers.json")
print(f"[✓] Total questions answered: {len(answers)}")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
