"""
IR Hunting Report Builder - Case Analysis Script
Analyzes all 5 incident response cases and structures the data for report generation
"""

import json
from datetime import datetime

def analyze_case(case):
    """Analyze a single IR case and extract key details"""
    print(f"\n{'='*80}")
    print(f"CASE {case['id']}: {case['title']}")
    print(f"Code: {case['code']}")
    print(f"{'='*80}")
    
    # Extract logs
    print(f"\n📋 LOGS ({len(case['logs'])} entries):")
    for log in case['logs']:
        print(f"  • {log}")
    
    # Extract telemetry
    print(f"\n🔍 TELEMETRY ({len(case['telemetry'])} alerts):")
    for tel in case['telemetry']:
        print(f"  • {tel}")
    
    # Extract palette data
    palette = case['palette']
    print(f"\n🎨 PALETTE DATA:")
    print(f"  Title Suggestions: {len(palette['title_suggestions'])}")
    for i, title in enumerate(palette['title_suggestions'], 1):
        print(f"    {i}. {title}")
    
    print(f"\n  MITRE Techniques: {', '.join(palette['mitre'])}")
    print(f"  Hosts: {', '.join(palette['hosts'])}")
    print(f"  Accounts: {', '.join(palette['accounts'])}")
    print(f"  IOCs: {', '.join(palette['iocs'])}")
    
    # Extract hints
    print(f"\n💡 HINTS:")
    for hint in case['hints']:
        print(f"  • {hint}")
    
    return case

def extract_timestamp_from_logs(logs):
    """Extract the earliest timestamp from logs"""
    timestamps = []
    for log in logs:
        # Extract timestamp (format: 2025-07-24T22:47:00Z)
        if log.startswith('20'):
            ts_str = log.split()[0]
            timestamps.append(ts_str)
    
    return timestamps[0] if timestamps else "Unknown"

def main():
    print("="*80)
    print("IR HUNTING REPORT BUILDER - CASE ANALYSIS")
    print("="*80)
    
    # Load scenarios
    with open('ir_scenarios.json', 'r') as f:
        scenarios = json.load(f)
    
    print(f"\n✅ Loaded {len(scenarios)} incident response cases")
    
    # Analyze each case
    analyzed_cases = []
    for scenario in scenarios:
        case_data = analyze_case(scenario)
        analyzed_cases.append(case_data)
    
    # Summary
    print(f"\n{'='*80}")
    print("ANALYSIS SUMMARY")
    print(f"{'='*80}")
    print(f"Total Cases: {len(analyzed_cases)}")
    print(f"\nCase Codes:")
    for case in analyzed_cases:
        print(f"  • {case['code']}: {case['title']}")
    
    print(f"\n✅ ANALYSIS COMPLETE - Ready for report generation")

if __name__ == '__main__':
    main()
