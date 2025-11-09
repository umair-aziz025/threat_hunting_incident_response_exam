import requests
import json

print("=" * 80)
print("IR HUNTING REPORT - INITIAL EXPLORATION")
print("=" * 80)

base_url = "http://127.0.0.1:8080"

# Try different endpoints
endpoints = [
    "/",
    "/api/cases",
    "/api/newround",
    "/api/case1",
    "/api/case2",
    "/api/case3",
    "/api/case4",
    "/api/case5",
]

print("\n🔍 Testing API Endpoints:")
print("-" * 80)

for endpoint in endpoints:
    try:
        url = base_url + endpoint
        print(f"\n📡 Testing: {url}")
        response = requests.get(url, timeout=5)
        print(f"   Status: {response.status_code}")
        
        # Try to parse as JSON
        try:
            data = response.json()
            print(f"   Response Type: JSON")
            print(f"   Keys: {list(data.keys()) if isinstance(data, dict) else 'List/Other'}")
            
            # Save first 500 chars
            preview = json.dumps(data, indent=2)[:500]
            print(f"   Preview:\n{preview}")
            
        except:
            # Not JSON, show text preview
            print(f"   Response Type: Text/HTML")
            print(f"   Length: {len(response.text)} chars")
            print(f"   Preview: {response.text[:200]}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")

print("\n" + "=" * 80)
