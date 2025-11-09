import requests
import json

print("=" * 80)
print("EDR DETECTION EXTRACTION")
print("=" * 80)

base_url = "http://127.0.0.1:8080"

# Call /api/newround to get detections
print("\n[*] Requesting new round from EDR server...")

try:
    response = requests.get(f"{base_url}/api/newround")
    data = response.json()
    
    print(f"[✓] Success!")
    print(f"    Round ID: {data.get('round_id')}")
    
    detections = data.get('detections', [])
    print(f"    Total Detections: {len(detections)}")
    
    # Save all detections
    with open('edr_detections.json', 'w') as f:
        json.dump(detections, f, indent=2)
    
    print(f"\n[✓] Saved all detections to: edr_detections.json")
    
    # Display summary
    print("\n" + "=" * 80)
    print("DETECTION SUMMARY")
    print("=" * 80)
    
    for i, det in enumerate(detections, 1):
        print(f"\n[{i}] {det.get('title')}")
        print(f"    Category: {det.get('category')}")
        print(f"    Severity: {det.get('severity')}")
        print(f"    Host: {det.get('host')}")
        print(f"    User: {det.get('user')}")
        print(f"    Image: {det.get('image')}")
        if det.get('mitre'):
            print(f"    MITRE: {', '.join(det.get('mitre', []))}")
        if det.get('kill_chain'):
            print(f"    Kill Chain: {', '.join(det.get('kill_chain', []))}")
    
    print("\n" + "=" * 80)
    print("EXTRACTION COMPLETE")
    print("=" * 80)
    print(f"\nNext: Analyze each detection to determine True Positive vs False Positive")
    
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()
