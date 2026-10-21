import zipfile, re, os

docx_path = r'C:\Users\ASUS\Desktop\Hackathons\MOSIP\MOSIP Inji Playground Blueprint.docx'
out_path = r'C:\Users\ASUS\Desktop\Hackathons\MOSIP\blueprint_raw.txt'

with zipfile.ZipFile(docx_path, 'r') as z:
    with z.open('word/document.xml') as f:
        xml = f.read().decode('utf-8')

# Remove XML tags
text = re.sub(r'<[^>]+>', '', xml)
# Clean entities
text = text.replace('&amp;', '&')
text = text.replace('&lt;', '<')
text = text.replace('&gt;', '>')
text = text.replace('&apos;', "'")
text = text.replace('&quot;', '"')
# Collapse whitespace but preserve newlines
lines = text.split('\n')
cleaned = []
for line in lines:
    stripped = line.strip()
    if stripped:
        cleaned.append(stripped)

final = '\n'.join(cleaned)

with open(out_path, 'w', encoding='utf-8') as f:
    f.write(final)

char_count = len(final)
line_count = final.count('\n')
print(f"DONE. Characters: {char_count}, Lines: {line_count}")
