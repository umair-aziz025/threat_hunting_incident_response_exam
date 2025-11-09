import requests
import json

print("=" * 80)
print("IR HUNTING REPORT - SCENARIOS EXTRACTION")
print("=" * 80)

url = "http://127.0.0.1:8080/api/scenarios"

print(f"\n📡 Fetching: {url}")
response = requests.get(url)

if response.status_code == 200:
    print(f"✅ Status: {response.status_code}")
    
    try:
        data = response.json()
        print(f"\n📊 Data Type: {type(data)}")
        print(f"📊 Number of scenarios: {len(data) if isinstance(data, list) else 'N/A'}")
        
        # Save full data
        with open('ir_scenarios.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"✅ Saved to: ir_scenarios.json")
        
        # Display overview
        print("\n" + "=" * 80)
        print("SCENARIOS OVERVIEW")
        print("=" * 80)
        
        if isinstance(data, list):
            for i, scenario in enumerate(data, 1):
                print(f"\n{'='*80}")
                print(f"SCENARIO {i}: {scenario.get('title', 'N/A')}")
                print(f"{'='*80}")
                print(f"Type: {scenario.get('type', 'N/A')}")
                print(f"Description: {scenario.get('description', 'N/A')[:200]}...")
                
                if 'evidence' in scenario:
                    print(f"\n📋 Evidence Items: {len(scenario['evidence'])}")
                    for j, ev in enumerate(scenario['evidence'][:3], 1):
                        print(f"   {j}. {ev.get('type', 'N/A')}: {ev.get('description', 'N/A')[:80]}...")
                
                if 'questions' in scenario:
                    print(f"\n❓ Questions: {len(scenario['questions'])}")
                    for j, q in enumerate(scenario['questions'][:3], 1):
                        print(f"   {j}. {q[:80] if isinstance(q, str) else q.get('question', 'N/A')[:80]}...")
        
        print("\n" + "=" * 80)
        print(f"✅ EXTRACTION COMPLETE - {len(data)} scenarios found")
        print("=" * 80)
        
    except Exception as e:
        print(f"❌ Error parsing JSON: {e}")
        print(f"Raw response: {response.text[:500]}")
else:
    print(f"❌ Status: {response.status_code}")
    print(f"Response: {response.text[:500]}")
