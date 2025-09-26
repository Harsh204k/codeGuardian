import argparse, json, pandas as pd, pathlib

def parse_osv(osv_path):
    p = pathlib.Path(osv_path)
    if not p.exists(): return pd.DataFrame(columns=["Package","Version","Ecosystem","CVE","CVSS","Fixed Version","Source"])
    import json
    data = json.loads(p.read_text(encoding="utf-8"))
    rows=[]
    for res in data.get("results", []):
        src = res.get("source", {}).get("path") or res.get("source", "")
        for pkg in res.get("packages", []):
            pname = pkg.get("package",{}).get("name","")
            eco   = pkg.get("package",{}).get("ecosystem","")
            vers  = pkg.get("version","")
            for v in pkg.get("vulnerabilities", []):
                cve = v.get("id","")
                cvss = ""
                sev = v.get("severity") or []
                if sev:
                    try:
                        cvss = sev[0].get("score", "")
                    except Exception:
                        pass
                fixed = ""
                for aff in v.get("affected",[]):
                    rngs = aff.get("ranges",[])
                    for r in rngs:
                        for ev in r.get("events",[]):
                            if "fixed" in ev: fixed = ev.get("fixed")
                rows.append({"Package":pname,"Version":vers,"Ecosystem":eco,"CVE":cve,"CVSS":cvss,"Fixed Version":fixed,"Source":src})
    return pd.DataFrame(rows)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--startup", required=True, help="Startup name for final file naming")
    ap.add_argument("--findings", default="report/stage1_results.xlsx")
    ap.add_argument("--osv", default="report/osv_report.json")
    ap.add_argument("--metrics", default="report/metrics.json")
    ap.add_argument("--out", default="report")
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
    findings_df = pd.read_excel(args.findings)
    cve_df = parse_osv(args.osv)
    metrics = {}
    mp = pathlib.Path(args.metrics)
    if mp.exists():
        metrics = json.loads(mp.read_text(encoding="utf-8"))
    metrics_df = pd.DataFrame([{
        "TP": metrics.get("TP",""),
        "FP": metrics.get("FP",""),
        "FN": metrics.get("FN",""),
        "Precision": round(metrics.get("precision",0.0),4) if metrics else "",
        "Recall":    round(metrics.get("recall",0.0),4) if metrics else "",
        "F1":        round(metrics.get("f1",0.0),4) if metrics else "",
        "ms/KLoC":   round(metrics.get("ms_per_kloc",0.0),2) if metrics else "",
    }])

    out_xlsx = out_dir / f"GC_PS_01_{args.startup}.xlsx"
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as xw:
        findings_df.to_excel(xw, sheet_name="Findings", index=False)
        (cve_df if not cve_df.empty else pd.DataFrame(columns=["Package","Version","Ecosystem","CVE","CVSS","Fixed Version","Source"])
        ).to_excel(xw, sheet_name="Dependencies (CVE)", index=False)
        metrics_df.to_excel(xw, sheet_name="Metrics", index=False)
    print(f"✅ Wrote final workbook → {out_xlsx}")

if __name__ == "__main__":
    main()
