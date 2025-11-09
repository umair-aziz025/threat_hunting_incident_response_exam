import requests
from bs4 import BeautifulSoup
import json

print("=" * 80)
print("IR HUNTING REPORT - HTML ANALYSIS")
print("=" * 80)

url = "http://127.0.0.1:8080"
response = requests.get(url)
html = response.text

# Save HTML
with open('ir_report_page.html', 'w', encoding='utf-8') as f:
    f.write(html)
print("\n✅ Saved HTML to: ir_report_page.html")

# Parse HTML
soup = BeautifulSoup(html, 'html.parser')

# Find title
title = soup.find('title')
print(f"\n📄 Page Title: {title.text if title else 'N/A'}")

# Look for scripts
print("\n🔍 Analyzing JavaScript...")
scripts = soup.find_all('script')
print(f"   Found {len(scripts)} script tags")

# Look for API calls or data in scripts
for i, script in enumerate(scripts):
    if script.string and ('api' in script.string.lower() or 'case' in script.string.lower() or 'fetch' in script.string.lower()):
        print(f"\n📜 Script #{i+1} (contains API/case/fetch):")
        # Show first 500 chars
        content = script.string[:800]
        print(content)
        print("..." if len(script.string) > 800 else "")

# Look for forms
forms = soup.find_all('form')
print(f"\n📝 Forms found: {len(forms)}")

# Look for buttons
buttons = soup.find_all('button')
print(f"\n🔘 Buttons found: {len(buttons)}")
for btn in buttons[:5]:
    print(f"   - {btn.get_text(strip=True)[:50]}")

# Look for divs with case IDs
case_divs = soup.find_all(['div', 'section'], class_=lambda x: x and 'case' in str(x).lower())
print(f"\n📦 Case-related elements: {len(case_divs)}")

print("\n" + "=" * 80)
