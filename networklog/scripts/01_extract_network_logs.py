import requests
import json
from collections import Counter

print("=" * 80)
print("EXTRACTING NETWORK LOGS FROM IR SERVER")
print("=" * 80)

base_url = "http://127.0.0.1:8080/api/logs"
all_logs = []

# Fetch all pages
print("\n[*] Fetching logs from server...")
for page in range(1, 6):  # 5 pages total
    try:
        response = requests.get(f"{base_url}?page={page}")
        data = response.json()
        logs = data.get('results', [])
        all_logs.extend(logs)
        print(f"    Page {page}/5: {len(logs)} records fetched")
    except Exception as e:
        print(f"    ❌ Error on page {page}: {e}")

print(f"\n[✓] Total logs extracted: {len(all_logs)}")

# Save all logs
with open('all_network_logs.json', 'w') as f:
    json.dump(all_logs, f, indent=2)
print(f"[✓] Saved to: all_network_logs.json")

# Analyze log structure
print("\n" + "=" * 80)
print("LOG STRUCTURE ANALYSIS")
print("=" * 80)

if all_logs:
    sample_log = all_logs[0]
    print(f"\nSample Log (ID: {sample_log.get('id')}):")
    print(json.dumps(sample_log, indent=2))
    
    # Get all unique fields
    all_fields = set()
    for log in all_logs:
        all_fields.update(log.keys())
    
    print(f"\n[*] All available fields ({len(all_fields)}):")
    for field in sorted(all_fields):
        print(f"    - {field}")

# Protocol breakdown
print("\n" + "=" * 80)
print("PROTOCOL DISTRIBUTION")
print("=" * 80)

protocols = Counter([log.get('proto', 'unknown') for log in all_logs])
apps = Counter([log.get('app', 'unknown') for log in all_logs])

print("\n[*] By Protocol:")
for proto, count in protocols.most_common():
    print(f"    {proto}: {count} logs")

print("\n[*] By Application:")
for app, count in apps.most_common():
    print(f"    {app}: {count} logs")

# IP analysis
print("\n" + "=" * 80)
print("IP ADDRESS ANALYSIS")
print("=" * 80)

src_ips = Counter([log.get('src_ip', 'unknown') for log in all_logs])
dst_ips = Counter([log.get('dst_ip', 'unknown') for log in all_logs])

print("\n[*] Top 10 Source IPs:")
for ip, count in src_ips.most_common(10):
    print(f"    {ip}: {count} connections")

print("\n[*] Top 10 Destination IPs:")
for ip, count in dst_ips.most_common(10):
    print(f"    {ip}: {count} connections")

# DNS specific analysis
dns_logs = [log for log in all_logs if log.get('app') == 'DNS']
print("\n" + "=" * 80)
print(f"DNS LOGS ANALYSIS ({len(dns_logs)} total)")
print("=" * 80)

if dns_logs:
    # Check for qname and qtype fields
    dns_sample = dns_logs[0]
    print(f"\nDNS Log Sample:")
    print(json.dumps(dns_sample, indent=2))
    
    if 'qname' in dns_sample:
        qnames = Counter([log.get('qname', '') for log in dns_logs])
        print(f"\n[*] Top 15 DNS Query Names:")
        for qname, count in qnames.most_common(15):
            print(f"    {qname}: {count} queries")
    
    if 'qtype' in dns_sample:
        qtypes = Counter([log.get('qtype', '') for log in dns_logs])
        print(f"\n[*] DNS Query Types:")
        for qtype, count in qtypes.most_common():
            print(f"    {qtype}: {count} queries")

# HTTP/HTTPS analysis
http_logs = [log for log in all_logs if log.get('app') in ['HTTP', 'HTTPS']]
print("\n" + "=" * 80)
print(f"HTTP/HTTPS LOGS ANALYSIS ({len(http_logs)} total)")
print("=" * 80)

if http_logs:
    http_sample = http_logs[0]
    print(f"\nHTTP/HTTPS Log Sample:")
    print(json.dumps(http_sample, indent=2))
    
    if 'method' in http_sample:
        methods = Counter([log.get('method', '') for log in http_logs])
        print(f"\n[*] HTTP Methods:")
        for method, count in methods.most_common():
            print(f"    {method}: {count} requests")
    
    if 'host' in http_sample:
        hosts = Counter([log.get('host', '') for log in http_logs])
        print(f"\n[*] Top 10 HTTP/HTTPS Hosts:")
        for host, count in hosts.most_common(10):
            print(f"    {host}: {count} requests")

# ICMP analysis
icmp_logs = [log for log in all_logs if log.get('app') == 'ICMP']
print("\n" + "=" * 80)
print(f"ICMP LOGS ANALYSIS ({len(icmp_logs)} total)")
print("=" * 80)

if icmp_logs:
    icmp_sample = icmp_logs[0]
    print(f"\nICMP Log Sample:")
    print(json.dumps(icmp_sample, indent=2))
    
    icmp_src = Counter([log.get('src_ip', '') for log in icmp_logs])
    icmp_dst = Counter([log.get('dst_ip', '') for log in icmp_logs])
    
    print(f"\n[*] ICMP Source IPs:")
    for ip, count in icmp_src.most_common():
        print(f"    {ip}: {count} packets")
    
    print(f"\n[*] ICMP Destination IPs:")
    for ip, count in icmp_dst.most_common():
        print(f"    {ip}: {count} packets")

print("\n" + "=" * 80)
print("EXTRACTION COMPLETE ✓")
print("=" * 80)
print("\nNext step: Run analysis script to find exfiltration and C2 activities")
