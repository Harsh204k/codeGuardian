import joblib
from pathlib import Path

_model = None

def _read_snippet(path, line, radius=60):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(0, (line or 1)-1-radius); e = min(len(lines), (line or 1)-1+radius)
        return "\n".join(lines[s:e])
    except:
        return ""

def _featurize(snippet: str, rule_id: str, cwe: str):
    lower = snippet.lower()
    return {
        "ruleId": rule_id or "",
        "cwe": cwe or "",
        "len": len(snippet),
        "plus_count": snippet.count("+"),
        "concat_sql": int(("select" in lower or "insert" in lower or "update" in lower or "delete" in lower) and ("+" in snippet or "concat" in lower)),
        "has_exec": int("runtime.getruntime().exec" in lower or "processbuilder" in lower),
        "has_header": int("addheader" in lower or "setheader" in lower or "sendredirect" in lower),
        "has_getparam": int("getparameter" in lower or "getquerystring" in lower or "getheader(" in lower or "getreader().readline" in lower),
        "has_writer": int("getwriter().print" in lower or "getwriter().println" in lower or "out.print" in lower),
        "has_md5_sha1": int("messagedigest.getinstance(\"md5\"" in lower or "messagedigest.getinstance(\"sha1\"" in lower),
        "aes_ecb": int("cipher.getinstance(\"aes/ecb" in lower),
        "path_file": int("new file(" in lower or "paths.get(" in lower),
        "xxe_factory": int("documentbuilderfactory.newinstance(" in lower or "saxparserfactory.newinstance(" in lower or "xmlinputfactory.newinstance(" in lower),
    }

def load_model(path="models/reranker_java.joblib"):
    global _model
    if _model is None:
        _model = joblib.load(path)
    return _model

def score_findings(findings, threshold=0.35):
    \"\"\"Filter a list of Finding objects by ML probability.\"\"\"
    if not findings:
        return findings
    try:
        import pandas as pd
    except Exception:
        return findings

    model = load_model()
    rows = []
    for f in findings:
        snip = _read_snippet(f.file, getattr(f, "line", 0) or 0)
        rows.append(_featurize(snip, getattr(f, "rule_id", ""), getattr(f, "cwe", "")))
    X = pd.DataFrame(rows)
    probs = model.predict_proba(X)[:,1]
    keep = [f for f,p in zip(findings, probs) if p >= threshold]
    return keep
