import pandas as pd
from engine.risk_scorer import calculate_risk_score, get_risk_level, calculate_project_risk

def export_excel(findings, out_path, cve_findings=None):
    """Export findings to Excel with risk scoring and CVE data."""
    
    # Static analysis findings with risk scores
    rows = []
    for i, f in enumerate(findings, start=1):
        risk_score = calculate_risk_score(f)
        risk_level = get_risk_level(risk_score)
        
        rows.append({
            "Ser": i,
            "Name of Application Tested": f.app,
            "Language": f.language,
            "Vulnerability Found": f.name + (f.cwe and f" ({f.cwe})" or ""),
            "CVE": "",  # Static analysis findings don't have CVEs
            "File Name": f.file,
            "Function Name": getattr(f, 'function_name', 'unknown'),
            "Line of Code": f.line,
            "Detection Accuracy": round(f.confidence, 2),
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Severity": f.severity
        })
    
    # Add CVE findings if provided
    if cve_findings:
        for cve in cve_findings:
            risk_score = calculate_risk_score(cve)
            risk_level = get_risk_level(risk_score)
            
            rows.append({
                "Ser": len(rows) + 1,
                "Name of Application Tested": findings[0].app if findings else "AppUnderTest",
                "Language": "dependency",
                "Vulnerability Found": f"Vulnerable Dependency: {cve.package}",
                "CVE": cve.cve_id,
                "File Name": f"dependency: {cve.package}=={cve.version}",
                "Function Name": "N/A",
                "Line of Code": 0,
                "Detection Accuracy": 1.0,  # CVE matches are 100% accurate
                "Risk Score": risk_score,
                "Risk Level": risk_level,
                "Severity": cve.severity
            })
    
    df = pd.DataFrame(rows, columns=[
        "Ser","Name of Application Tested","Language","Vulnerability Found",
        "CVE","File Name","Function Name","Line of Code","Detection Accuracy",
        "Risk Score","Risk Level","Severity"
    ])
    
    # Sort by Risk Score descending for maximum impact
    if not df.empty:
        df = df.sort_values("Risk Score", ascending=False)
    
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create Excel with multiple sheets
    with pd.ExcelWriter(out_path, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Security Findings', index=False)
        
        # CVE Summary sheet
        if cve_findings:
            cve_rows = []
            for cve in cve_findings:
                cve_rows.append({
                    "CVE ID": cve.cve_id,
                    "Package": cve.package,
                    "Version": cve.version,
                    "Severity": cve.severity,
                    "CVSS Score": cve.cvss_score,
                    "Fixed Version": cve.fixed_version or "Not available",
                    "Description": cve.description
                })
            cve_df = pd.DataFrame(cve_rows)
            cve_df.to_excel(writer, sheet_name='CVE Details', index=False)
        
        # Summary sheet with risk analysis
        all_findings_for_risk = findings + (cve_findings or [])
        project_risk = calculate_project_risk(all_findings_for_risk)
        
        summary_data = {
            "Metric": [
                "Total Findings", 
                "Static Analysis Findings", 
                "CVE Findings", 
                "Overall Project Risk Score",
                "Overall Project Risk Level",
                "Critical Risk Findings",
                "High Risk Findings",
                "Medium Risk Findings",
                "Low Risk Findings",
                "Average Risk Score",
                "Critical/High Severity"
            ],
            "Count": [
                len(rows),
                len(findings),
                len(cve_findings) if cve_findings else 0,
                project_risk["overall_score"],
                project_risk["risk_level"],
                project_risk["critical_count"],
                project_risk["high_count"],
                project_risk["medium_count"],
                project_risk["low_count"],
                project_risk["avg_score"],
                len([f for f in findings if f.severity in ["CRITICAL", "HIGH"]]) + 
                len([c for c in (cve_findings or []) if c.severity in ["CRITICAL", "HIGH"]])
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Risk Summary', index=False)
        
    print(f"Excel report with risk analysis: {out_path}")
    print(f"Project Risk Level: {project_risk['risk_level'] if 'project_risk' in locals() else 'UNKNOWN'}")
    print(f"Total findings: {len(rows)}, High-risk: {project_risk['critical_count'] + project_risk['high_count'] if 'project_risk' in locals() else 'N/A'}")
