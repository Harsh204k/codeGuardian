from html import escape
def export_html(findings, out_path):
    rows = []
    for f in findings:
        rows.append(f"""
<tr>
  <td>{escape(f.id)}</td><td>{escape(f.language)}</td><td>{escape(f.name)}</td>
  <td>{escape(f.cwe or "")}</td><td>{escape(f.owasp or "")}</td>
  <td>{escape(f.severity)}</td><td>{escape(str(round(f.confidence,2)))}</td>
  <td><code>{escape(f.file)}:{f.line}</code></td>
</tr>""")
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>CodeGuardian Results</title></head>
<body><h2>Findings ({len(findings)})</h2>
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>ID</th><th>Lang</th><th>Name</th><th>CWE</th><th>OWASP</th><th>Severity</th><th>Conf</th><th>Location</th></tr>
{''.join(rows)}
</table></body></html>"""
    out_path.write_text(html, encoding="utf-8")
