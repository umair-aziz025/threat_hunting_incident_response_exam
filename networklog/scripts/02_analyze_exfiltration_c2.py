import json
import base64
import re
from collections import Counter, defaultdict

print("=" * 80)
print("NETWORK TRAFFIC ANALYSIS - EXFILTRATION & C2 DETECTION")
print("=" * 80)

# Load logs
with open('all_network_logs.json', 'r') as f:
    all_logs = json.load(f)

print(f"\n[*] Loaded {len(all_logs)} network logs")

# Separate by application
dns_logs = [log for log in all_logs if log.get('app') == 'DNS']
http_logs = [log for log in all_logs if log.get('app') == 'HTTP']
https_logs = [log for log in all_logs if log.get('app') == 'HTTPS']
icmp_logs = [log for log in all_logs if log.get('app') == 'ICMP']

print(f"    DNS: {len(dns_logs)}")
print(f"    HTTP: {len(http_logs)}")
print(f"    HTTPS: {len(https_logs)}")
print(f"    ICMP: {len(icmp_logs)}")

# ============================================================================
# DNS EXFILTRATION ANALYSIS
# ============================================================================
print("\n" + "=" * 80)
print("DNS EXFILTRATION ANALYSIS")
print("=" * 80)

# Look for suspicious DNS patterns
suspicious_domains = []
for log in dns_logs:
    qname = log.get('dns_qname', '')
    
    # Check for exfil-related domains
    if 'exfil' in qname.lower() or 'attacker' in qname.lower():
        suspicious_domains.append(log)
    
    # Check for unusually long subdomains (common in DNS exfil)
    if qname:
        parts = qname.split('.')
        for part in parts:
            if len(part) > 30:  # Long subdomain = possible encoded data
                suspicious_domains.append(log)
                break

print(f"\n[*] Found {len(suspicious_domains)} suspicious DNS queries")

# Analyze suspicious domains
if suspicious_domains:
    print(f"\n[!] SUSPICIOUS DNS QUERIES:")
    
    # Group by base domain
    domain_groups = defaultdict(list)
    for log in suspicious_domains:
        qname = log.get('dns_qname', '')
        # Extract base domain (last 2 parts)
        parts = qname.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            domain_groups[base_domain].append(log)
    
    for domain, logs in domain_groups.items():
        print(f"\n    Base Domain: {domain}")
        print(f"    Query Count: {len(logs)}")
        print(f"    Source IPs: {set([log.get('src_ip') for log in logs])}")
        print(f"    Query Types: {set([log.get('dns_qtype') for log in logs])}")
        print(f"    Destination IPs: {set([log.get('dst_ip') for log in logs])}")
        
        # Show sample queries
        print(f"    Sample Queries:")
        for log in logs[:5]:
            print(f"      - {log.get('dns_qname')} (Type: {log.get('dns_qtype')}, Time: {log.get('timestamp')})")

# Analyze data size by DNS queries
print("\n[*] Analyzing data transfer sizes...")
host_sizes = defaultdict(int)
for log in dns_logs:
    qname = log.get('dns_qname', '')
    size = log.get('size', 0)
    if qname:
        # Extract base domain or use full qname
        parts = qname.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            host_sizes[base_domain] += size

print(f"\n[*] Top DNS domains by data size:")
for domain, size in sorted(host_sizes.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"    {domain}: {size} bytes")

# ============================================================================
# ICMP EXFILTRATION ANALYSIS
# ============================================================================
print("\n" + "=" * 80)
print("ICMP EXFILTRATION ANALYSIS")
print("=" * 80)

# Analyze ICMP traffic
icmp_src = Counter([log.get('src_ip') for log in icmp_logs])
icmp_dst = Counter([log.get('dst_ip') for log in icmp_logs])
icmp_types = Counter([log.get('icmp_type') for log in icmp_logs])

print(f"\n[*] ICMP Traffic Summary:")
print(f"    Total ICMP packets: {len(icmp_logs)}")
print(f"    Unique source IPs: {len(icmp_src)}")
print(f"    Unique destination IPs: {len(icmp_dst)}")

print(f"\n[*] ICMP Types:")
for itype, count in icmp_types.most_common():
    print(f"    {itype}: {count} packets")

# Look for suspicious ICMP patterns (large payloads, unusual destinations)
suspicious_icmp = []
for log in icmp_logs:
    payload = log.get('payload', '')
    size = log.get('size', 0)
    
    # Check for data in payload
    if payload and payload != 'abcd1234':  # Not standard ping payload
        suspicious_icmp.append(log)
    
    # Check for unusually large ICMP packets
    if size > 100:  # Normal ping is ~64-98 bytes
        if log not in suspicious_icmp:
            suspicious_icmp.append(log)

print(f"\n[!] Suspicious ICMP packets: {len(suspicious_icmp)}")

if suspicious_icmp:
    print(f"\n[*] Suspicious ICMP Details:")
    
    # Group by source-destination pair
    icmp_pairs = defaultdict(list)
    for log in suspicious_icmp:
        pair = f"{log.get('src_ip')} -> {log.get('dst_ip')}"
        icmp_pairs[pair].append(log)
    
    for pair, logs in icmp_pairs.items():
        print(f"\n    Connection: {pair}")
        print(f"    Packet Count: {len(logs)}")
        print(f"    ICMP Types: {set([log.get('icmp_type') for log in logs])}")
        print(f"    Avg Size: {sum([log.get('size', 0) for log in logs]) / len(logs):.1f} bytes")
        
        # Analyze payloads
        payloads = [log.get('payload', '') for log in logs if log.get('payload')]
        if payloads:
            print(f"    Sample Payloads:")
            for payload in payloads[:3]:
                print(f"      - {payload[:100]}...")
                
                # Try to detect encoding
                if re.match(r'^[A-Za-z0-9+/=]+$', payload):
                    print(f"        [*] Possibly Base64 encoded")
                elif re.match(r'^[0-9a-fA-F]+$', payload):
                    print(f"        [*] Possibly Hex encoded")

# ============================================================================
# HTTPS EXFILTRATION ANALYSIS
# ============================================================================
print("\n" + "=" * 80)
print("HTTPS EXFILTRATION ANALYSIS")
print("=" * 80)

# Look for large POST requests (common for exfiltration)
large_posts = []
for log in https_logs:
    method = log.get('method', '')
    size = log.get('size', 0)
    
    if method == 'POST' and size > 1000:  # Large POST request
        large_posts.append(log)

print(f"\n[*] Found {len(large_posts)} large HTTPS POST requests")

# Analyze by host and size
https_host_sizes = defaultdict(int)
https_host_methods = defaultdict(list)
for log in https_logs:
    host = log.get('host', '') or log.get('sni', '')
    size = log.get('size', 0)
    method = log.get('method', '')
    
    if host:
        https_host_sizes[host] += size
        https_host_methods[host].append(method)

print(f"\n[*] Top HTTPS hosts by data transfer:")
for host, size in sorted(https_host_sizes.items(), key=lambda x: x[1], reverse=True)[:10]:
    methods = Counter(https_host_methods[host])
    print(f"    {host}: {size} bytes")
    print(f"      Methods: {dict(methods)}")

# Find largest single HTTPS transfer
largest_https = max(https_logs, key=lambda x: x.get('size', 0))
print(f"\n[!] Largest HTTPS Transfer:")
print(f"    Host/SNI: {largest_https.get('host') or largest_https.get('sni')}")
print(f"    Method: {largest_https.get('method')}")
print(f"    URI: {largest_https.get('uri')}")
print(f"    Size: {largest_https.get('size')} bytes")
print(f"    Source: {largest_https.get('src_ip')}")
print(f"    Destination: {largest_https.get('dst_ip')}")
print(f"    Timestamp: {largest_https.get('timestamp')}")

# ============================================================================
# C2 DETECTION (HTTP/HTTPS)
# ============================================================================
print("\n" + "=" * 80)
print("C2 (COMMAND & CONTROL) DETECTION")
print("=" * 80)

# Analyze HTTP traffic for C2 patterns
print(f"\n[*] Analyzing HTTP traffic for C2 patterns...")

# Group HTTP requests by host to find beaconing
http_host_requests = defaultdict(list)
for log in http_logs:
    host = log.get('host', '')
    if host:
        http_host_requests[host].append(log)

print(f"\n[*] HTTP Hosts with multiple connections (potential C2):")
for host, logs in sorted(http_host_requests.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
    print(f"\n    Host: {host}")
    print(f"    Connection Count: {len(logs)}")
    print(f"    Source IPs: {set([log.get('src_ip') for log in logs])}")
    print(f"    Destination IPs: {set([log.get('dst_ip') for log in logs])}")
    print(f"    Methods: {Counter([log.get('method') for log in logs])}")
    print(f"    URIs: {set([log.get('uri', '') for log in logs if log.get('uri')])}")
    print(f"    User-Agents: {set([log.get('ua', '')[:50] for log in logs if log.get('ua')])}")
    
    # Look for commands at specific time
    for log in logs:
        if '04:30:10' in log.get('timestamp', ''):
            print(f"    [!] Activity at 04:30:10Z:")
            print(f"        URI: {log.get('uri')}")
            print(f"        Method: {log.get('method')}")
            print(f"        Payload: {log.get('payload', '')[:200]}")

# Analyze HTTPS for C2
print(f"\n[*] Analyzing HTTPS traffic for C2 patterns...")

https_host_requests = defaultdict(list)
for log in https_logs:
    sni = log.get('sni', '') or log.get('host', '')
    if sni:
        https_host_requests[sni].append(log)

print(f"\n[*] HTTPS Hosts with multiple connections (potential C2):")
for host, logs in sorted(https_host_requests.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
    print(f"\n    SNI/Host: {host}")
    print(f"    Connection Count: {len(logs)}")
    print(f"    Source IPs: {set([log.get('src_ip') for log in logs])}")
    print(f"    Destination IPs: {set([log.get('dst_ip') for log in logs])}")
    print(f"    Methods: {Counter([log.get('method') for log in logs])}")
    print(f"    URIs: {set([log.get('uri', '') for log in logs if log.get('uri')])}")

# ============================================================================
# FIND LARGEST DATA EXFILTRATION
# ============================================================================
print("\n" + "=" * 80)
print("LARGEST DATA EXFILTRATION BY HOST/DNS/SNI")
print("=" * 80)

all_host_sizes = {}

# Combine DNS, HTTP, HTTPS sizes
for domain, size in host_sizes.items():
    all_host_sizes[f"DNS:{domain}"] = size

for host, size in https_host_sizes.items():
    all_host_sizes[f"HTTPS:{host}"] = size

http_host_sizes = defaultdict(int)
for log in http_logs:
    host = log.get('host', '')
    size = log.get('size', 0)
    if host:
        http_host_sizes[host] += size

for host, size in http_host_sizes.items():
    all_host_sizes[f"HTTP:{host}"] = size

print(f"\n[*] Top 15 Hosts/Domains by Total Data Transfer:")
for host, size in sorted(all_host_sizes.items(), key=lambda x: x[1], reverse=True)[:15]:
    print(f"    {host}: {size} bytes")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE ✓")
print("=" * 80)
