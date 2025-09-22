def sev_score(sev): return {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(sev.upper(),2)
def rank_findings(findings):
    return sorted(findings, key=lambda f: (-sev_score(f.severity), -f.confidence, f.file, f.line))
