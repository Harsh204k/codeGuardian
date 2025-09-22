import pandas as pd
def export_excel(findings, out_path):
    rows = []
    for i, f in enumerate(findings, start=1):
        rows.append({
            "Ser": i,
            "Name of Application Tested": f.app,
            "Language": f.language,
            "Vulnerability Found": f.name + (f.cwe and f" ({f.cwe})" or ""),
            "CVE": "",  # deps sheet will carry CVEs separately
            "File Name": f.file,
            "Line of Code": f.line,
            "Detection Accuracy": round(f.confidence, 2),
        })
    df = pd.DataFrame(rows, columns=[
        "Ser","Name of Application Tested","Language","Vulnerability Found",
        "CVE","File Name","Line of Code","Detection Accuracy"
    ])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_excel(out_path, index=False)
