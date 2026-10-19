import os
import re

file_path = "backend/advanced_cti_processor.py"
if not os.path.exists(file_path):
    print(f"ERROR: {file_path} not found!")
    exit(1)

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

original = content

# 1. Add attack_technique to INDICATOR_TYPES
if '"attack_technique"' not in content:
    match = re.search(r'(INDICATOR_TYPES\s*=\s*\{)([^}]*)(\})', content)
    if match:
        inner = match.group(2).rstrip()
        if inner and not inner.endswith(','):
            inner += ','
        new_inner = inner + '\n    "attack_technique",\n'
        content = content[:match.start(2)] + new_inner + content[match.end(2):]
        print("[1/3] Added 'attack_technique' to INDICATOR_TYPES")
    else:
        print("[!] Could not auto-detect INDICATOR_TYPES format.")
else:
    print("[-] INDICATOR_TYPES already includes attack_technique.")

# 2. Inject handling into validate_indicator using lambda (fixes \d crash)
if 'if indicator_type == "attack_technique":' not in content and 'def validate_indicator' in content:
    injection = (
        '    if indicator_type == "attack_technique":\n'
        '        v = str(value or "").strip().upper()\n'
        '        if not re.match(r"^T\\d{4}(\\.\\d{3})?$", v):\n'
        '            raise ValueError("Invalid ATT&CK technique ID.")\n'
        '        return v\n'
    )
    pattern = re.compile(r'(def validate_indicator\([^)]*\):\n)')
    
    def replacer(m):
        return m.group(1) + injection
    
    content, count = pattern.subn(replacer, content, count=1)
    if count > 0:
        print("[2/3] Injected attack_technique validation into validate_indicator")
    else:
        print("[!] Could not inject into validate_indicator")
else:
    print("[-] validate_indicator already patched.")

# 3. Ensure `import re` exists
if not re.search(r'^\s*import re\b', content, re.MULTILINE):
    content = "import re\n" + content
    print("[3/3] Added 'import re' at the top")

if content != original:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("\n✅ SUCCESS: File patched. Restart the backend now.")
else:
    print("\n⚠ No changes made.")
