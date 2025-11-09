import json
import base64

print("=" * 80)
print("VERIFICATION - ALL ANSWERS")
print("=" * 80)

with open('all_network_logs.json', 'r') as f:
    all_logs = json.load(f)

print(f"\nLoaded {len(all_logs)} logs\n")

passed = 0
failed = 0
total = 0

# DNS Exfil
dns_exfil = [l for l in all_logs if l.get('app') == 'DNS' and 'exfil.attacker.net' in l.get('dns_qname', '')]
print("DNS EXFILTRATION:")
total += 1
if len(dns_exfil) == 6:
    print("  [PASS] Found 6 DNS exfil queries")
    passed += 1
else:
    print(f"  [FAIL] Expected 6, found {len(dns_exfil)}")
    failed += 1

total += 1
src = set([l.get('src_ip') for l in dns_exfil])
if '10.0.5.50' in src:
    print("  [PASS] Source: 10.0.5.50")
    passed += 1
else:
    print(f"  [FAIL] Source not 10.0.5.50, found {src}")
    failed += 1

total += 1
qtypes = set([l.get('dns_qtype') for l in dns_exfil])
if 'A' in qtypes and 'TXT' in qtypes:
    print("  [PASS] Query types: A, TXT")
    passed += 1
else:
    print(f"  [FAIL] Query types: {qtypes}")
    failed += 1

total += 1
dst = set([l.get('dst_ip') for l in dns_exfil])
if '10.0.0.53' in dst:
    print("  [PASS] Resolver: 10.0.0.53")
    passed += 1
else:
    print(f"  [FAIL] Resolver: {dst}")
    failed += 1

# ICMP Exfil
print("\nICMP EXFILTRATION:")
icmp_sus = [l for l in all_logs if l.get('app') == 'ICMP' and l.get('size', 0) > 100]

total += 1
if len(icmp_sus) == 8:
    print("  [PASS] Found 8 suspicious ICMP packets")
    passed += 1
else:
    print(f"  [FAIL] Expected 8, found {len(icmp_sus)}")
    failed += 1

total += 1
icmp_src = set([l.get('src_ip') for l in icmp_sus])
if '10.0.5.51' in icmp_src:
    print("  [PASS] Source: 10.0.5.51")
    passed += 1
else:
    print(f"  [FAIL] Source: {icmp_src}")
    failed += 1

total += 1
icmp_dst = set([l.get('dst_ip') for l in icmp_sus])
if '198.51.100.10' in icmp_dst:
    print("  [PASS] Destination: 198.51.100.10")
    passed += 1
else:
    print(f"  [FAIL] Destination: {icmp_dst}")
    failed += 1

total += 1
icmp_type = set([l.get('icmp_type') for l in icmp_sus])
if 'echo-request' in icmp_type:
    print("  [PASS] Type: echo-request")
    passed += 1
else:
    print(f"  [FAIL] Type: {icmp_type}")
    failed += 1

total += 1
payload = icmp_sus[0].get('payload', '') if icmp_sus else ''
if payload and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=.' for c in payload[:50]):
    print("  [PASS] Encoding: Base64")
    passed += 1
else:
    print("  [FAIL] Encoding not Base64")
    failed += 1

# HTTPS Exfil
print("\nHTTPS EXFILTRATION:")
https_logs = [l for l in all_logs if l.get('app') == 'HTTPS']
largest = max(https_logs, key=lambda x: x.get('size', 0)) if https_logs else None

total += 1
if largest and largest.get('size') == 150000:
    print("  [PASS] Size: 150000 bytes")
    passed += 1
else:
    print(f"  [FAIL] Size: {largest.get('size') if largest else 'N/A'}")
    failed += 1

total += 1
if largest and largest.get('method') == 'POST':
    print("  [PASS] Method: POST")
    passed += 1
else:
    print(f"  [FAIL] Method: {largest.get('method') if largest else 'N/A'}")
    failed += 1

total += 1
if largest and largest.get('uri') == '/sync/upload':
    print("  [PASS] URI: /sync/upload")
    passed += 1
else:
    print(f"  [FAIL] URI: {largest.get('uri') if largest else 'N/A'}")
    failed += 1

total += 1
host = (largest.get('sni') or largest.get('host')) if largest else None
if host == 'secure-updates.cdn-cloudsync.net':
    print("  [PASS] Host: secure-updates.cdn-cloudsync.net")
    passed += 1
else:
    print(f"  [FAIL] Host: {host}")
    failed += 1

# C2 HTTP
print("\nHTTP C2:")
http_logs = [l for l in all_logs if l.get('app') == 'HTTP']
c2_http = [l for l in http_logs if '/api/' in l.get('uri', '') or 'beacon' in l.get('uri', '')]

total += 1
if len(c2_http) == 5:
    print("  [PASS] Found 5 HTTP C2 requests")
    passed += 1
else:
    print(f"  [FAIL] Expected 5, found {len(c2_http)}")
    failed += 1

total += 1
c2_host = set([l.get('host') for l in c2_http])
if 'update-service.net' in c2_host:
    print("  [PASS] Host: update-service.net")
    passed += 1
else:
    print(f"  [FAIL] Host: {c2_host}")
    failed += 1

total += 1
c2_src = set([l.get('src_ip') for l in c2_http])
if '10.0.5.40' in c2_src:
    print("  [PASS] Source: 10.0.5.40")
    passed += 1
else:
    print(f"  [FAIL] Source: {c2_src}")
    failed += 1

total += 1
c2_dst = set([l.get('dst_ip') for l in c2_http])
if '203.0.113.55' in c2_dst:
    print("  [PASS] Destination: 203.0.113.55")
    passed += 1
else:
    print(f"  [FAIL] Destination: {c2_dst}")
    failed += 1

total += 1
cmd_log = [l for l in c2_http if '04:30:10' in l.get('timestamp', '')]
if cmd_log:
    try:
        decoded = base64.b64decode(cmd_log[0].get('payload', '')).decode('utf-8')
        if decoded == 'cmd:whoami':
            print("  [PASS] Command at 04:30:10Z: cmd:whoami")
            passed += 1
        else:
            print(f"  [FAIL] Command: {decoded}")
            failed += 1
    except:
        print("  [FAIL] Could not decode command")
        failed += 1
else:
    print("  [FAIL] No command at 04:30:10Z")
    failed += 1

# C2 HTTPS
print("\nHTTPS C2:")
https_c2 = [l for l in https_logs if '/v1/' in l.get('uri', '') or 'checkin' in l.get('uri', '')]

total += 1
if len(https_c2) == 3:
    print("  [PASS] Found 3 HTTPS C2 requests")
    passed += 1
else:
    print(f"  [FAIL] Expected 3, found {len(https_c2)}")
    failed += 1

total += 1
https_c2_src = set([l.get('src_ip') for l in https_c2])
if '10.0.5.30' in https_c2_src:
    print("  [PASS] Source: 10.0.5.30")
    passed += 1
else:
    print(f"  [FAIL] Source: {https_c2_src}")
    failed += 1

total += 1
https_c2_sni = set([l.get('sni') or l.get('host') for l in https_c2])
if 'cdn-cloudupdates.net' in https_c2_sni:
    print("  [PASS] SNI: cdn-cloudupdates.net")
    passed += 1
else:
    print(f"  [FAIL] SNI: {https_c2_sni}")
    failed += 1

total += 1
https_c2_dst = set([l.get('dst_ip') for l in https_c2])
if '198.51.100.23' in https_c2_dst:
    print("  [PASS] Destination: 198.51.100.23")
    passed += 1
else:
    print(f"  [FAIL] Destination: {https_c2_dst}")
    failed += 1

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Total Checks: {total}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Success Rate: {passed/total*100:.1f}%")

if failed == 0:
    print("\n*** ALL ANSWERS VERIFIED SUCCESSFULLY ***")
    print("Ready for exam submission!")
else:
    print(f"\nWarning: {failed} checks failed")

print("=" * 80)
