# --- create dirs ---
$dirs = @(
  "engine","engine\reporters","rules","demos","demos\vulnerable_py","demos\vulnerable_java","demos\vulnerable_php"
)
$dirs | ForEach-Object { if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null } }

# --- requirements.txt ---
@'
pyyaml
regex
pandas
openpyxl
rich
'@ | Set-Content requirements.txt -Encoding UTF8

# --- .cgignore ---
@'
*/.git/*
*/node_modules/*
*/build/*
*/dist/*
*/venv/*
*/.venv/*
'@ | Set-Content .cgignore -Encoding UTF8

# --- engine/__init__.py ---
New-Item -ItemType File -Path "engine\__init__.py" -Force | Out-Null


# --- cli.py ---
@'
#!/usr/bin/env python3
import argparse, sys, pathlib
from engine.walker import collect_files
from engine.rules_loader import load_rules
from engine.scanner import scan_files
from engine.ranker import rank_findings
from engine.reporters.excel_exporter import export_excel
from engine.reporters.sarif_exporter import export_sarif
from engine.reporters.html_reporter import export_html
from engine.fixes import apply_fix_interactive
from engine.deps import run_dependency_audit

def main():
    p = argparse.ArgumentParser("codeguardian")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Scan a repo or file path")
    s.add_argument("--path", required=True)
    s.add_argument("--format", default="excel,html,sarif")
    s.add_argument("--out", default="report")
    s.add_argument("--profile", choices=["strict","balanced","relaxed"], default="balanced")
    s.add_argument("--langs", default="auto", help="auto or csv: python,java,cpp,csharp,php")
    s.add_argument("--name", default="AppUnderTest")

    f = sub.add_parser("fix", help="Apply a quick fix by id")
    f.add_argument("--path", required=True)
    f.add_argument("--id", required=True)
    f.add_argument("--backup", action="store_true", default=True)

    d = sub.add_parser("deps", help="Dependency CVE audit (SBOM+OSV)")
    d.add_argument("--path", required=True)
    d.add_argument("--out", default="report")

    args = p.parse_args()
    out_dir = pathlib.Path(args.out)

    if args.cmd == "scan":
        files = collect_files(args.path, args.langs)
        rules = load_rules(args.langs)
        raw = scan_files(files, rules, profile=args.profile, appname=args.name)
        ranked = rank_findings(raw)
        out_dir.mkdir(parents=True, exist_ok=True)
        fmts = [x.strip() for x in args.format.split(",")]
        if "excel" in fmts: export_excel(ranked, out_dir / "stage1_results.xlsx")
        if "sarif" in fmts: export_sarif(ranked, out_dir / "results.sarif")
        if "html"  in fmts: export_html(ranked, out_dir / "results.html")
        print(f"Scanned {len(files)} files → {len(ranked)} findings. Reports in {out_dir}")

    elif args.cmd == "fix":
        ok = apply_fix_interactive(args.path, args.id, backup=args.backup)
        sys.exit(0 if ok else 2)

    elif args.cmd == "deps":
        run_dependency_audit(args.path, out_dir)

if __name__ == "__main__":
    main()
'@ | Set-Content cli.py -Encoding UTF8

# --- engine/walker.py ---
@'
import pathlib, fnmatch

DEFAULT_IGNORES = ["*/.git/*","*/node_modules/*","*/build/*","*/dist/*","*/venv/*","*/.venv/*"]

LANG_MAP = {
    ".py":"python",".java":"java",".c":"cpp",".h":"cpp",".cpp":"cpp",".hpp":"cpp",".cs":"csharp",".php":"php"
}

def load_ignores(root: str):
    ig = set(DEFAULT_IGNORES)
    cg = pathlib.Path(root) / ".cgignore"
    if cg.exists():
        for line in cg.read_text(encoding="utf-8", errors="ignore").splitlines():
            line=line.strip()
            if line and not line.startswith("#"): ig.add(line)
    return list(ig)

def is_ignored(path: str, ignores):
    return any(fnmatch.fnmatch(path, pat) for pat in ignores)

def collect_files(root: str, langs: str):
    rootp = pathlib.Path(root)
    ignores = load_ignores(root)
    targets = []
    for p in rootp.rglob("*"):
        if not p.is_file(): continue
        sp = str(p)
        if is_ignored(sp, ignores): continue
        lang = LANG_MAP.get(p.suffix.lower())
        if not lang: continue
        if langs != "auto" and lang not in langs.split(","): continue
        targets.append((lang, p))
    return targets
'@ | Set-Content engine\walker.py -Encoding UTF8

# --- engine/rules_loader.py ---
@'
import yaml, pathlib

def load_rules(langs: str):
    base = pathlib.Path(__file__).parent.parent / "rules"
    lang_list = ["python","java","cpp","csharp","php"] if langs=="auto" else [x.strip() for x in langs.split(",")]
    all_rules = []
    for lang in lang_list:
        f = base / f"{lang}.yml"
        if f.exists():
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore")) or {}
            for r in data.get("rules", []):
                r["language"] = lang
                all_rules.append(r)
    return all_rules
'@ | Set-Content engine\rules_loader.py -Encoding UTF8

# --- engine/scanner.py ---
@'
import re, uuid
from dataclasses import dataclass
@dataclass
class Finding:
    id: str; app: str; language: str; rule_id: str; name: str; file: str; line: int
    snippet: str; cwe: str; owasp: str; severity: str; confidence: float; why: str; quickfix: dict|None

def _iter_matches(content: str, pattern: str):
    rx = re.compile(pattern)
    for m in rx.finditer(content):
        line = content.count("\\n", 0, m.start()) + 1
        yield line

def scan_files(files, rules, profile="balanced", appname="App"):
    results = []
    prof_boost = {"strict": +0.05, "balanced": 0.0, "relaxed": -0.05}[profile]
    for lang, path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for r in rules:
            if r["language"] != lang: continue
            for ln in _iter_matches(text, r["pattern"]):
                fid = str(uuid.uuid4())[:8]
                snippet = lines[ln-1][:240] if 0 <= ln-1 < len(lines) else ""
                conf = max(0.0, min(1.0, float(r.get("confidence", 0.7)) + prof_boost))
                results.append(Finding(
                    id=f"{r['id']}-{fid}", app=appname, language=lang, rule_id=r["id"], name=r["name"],
                    file=str(path), line=ln, snippet=snippet, cwe=r.get("cwe",""), owasp=r.get("owasp","—"),
                    severity=r.get("severity","MEDIUM"), confidence=conf, why=r.get("why",""), quickfix=r.get("fix")
                ))
    return results
'@ | Set-Content engine\scanner.py -Encoding UTF8

# --- engine/ranker.py ---
@'
def sev_score(sev): return {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(sev.upper(),2)
def rank_findings(findings):
    return sorted(findings, key=lambda f: (-sev_score(f.severity), -f.confidence, f.file, f.line))
'@ | Set-Content engine\ranker.py -Encoding UTF8

# --- engine/explain.py (unused yet, kept for future LLM) ---
@'
def build_explanation(finding):
    return f"{finding.name}. {finding.why} (Mapped to {finding.cwe or '—'} / {finding.owasp or '—'})."
'@ | Set-Content engine\explain.py -Encoding UTF8

# --- engine/fixes.py ---
@'
import shutil, pathlib, uuid, re
def apply_fix_interactive(repo_path: str, finding_id: str, backup=True) -> bool:
    print("Enter file path containing the finding:")
    file_path = input().strip()
    p = pathlib.Path(file_path)
    if not p.exists():
        print("File not found."); return False
    text = p.read_text(encoding="utf-8", errors="ignore")
    changed = False
    if "shell=True" in text:
        new = text.replace("shell=True", "shell=False"); changed = True
    else:
        new = re.sub(r"(\\n)", "\\n# CODEGUARDIAN: Review and apply parameterized/safe API.\\n", text, count=1); changed = True
    if changed:
        if backup: shutil.copy(file_path, f"{file_path}.bak.{uuid.uuid4().hex[:6]}")
        p.write_text(new, encoding="utf-8"); print(f"Updated {file_path} (backup created)."); return True
    return False
'@ | Set-Content engine\fixes.py -Encoding UTF8

# --- engine/deps.py (stub; enable later with syft/osv-scanner) ---
@'
import subprocess, pathlib
def run_dependency_audit(path: str, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    sbom = outdir / "sbom.json"; osv = outdir / "osv_report.json"
    try:
        subprocess.run(["syft","packages",path,"-o","json"], check=True, stdout=sbom.open("w", encoding="utf-8"))
        subprocess.run(["osv-scanner","--sbom",str(sbom)], check=False, stdout=osv.open("w", encoding="utf-8"))
        print(f"Dependency audit complete → {osv}")
    except FileNotFoundError:
        print("Install syft and osv-scanner for dependency CVE audits.")
'@ | Set-Content engine\deps.py -Encoding UTF8

# --- reporters: excel ---
@'
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
'@ | Set-Content engine\reporters\excel_exporter.py -Encoding UTF8

# --- reporters: sarif ---
@'
import json
def export_sarif(findings, out_path):
    runs = [{
      "tool": {"driver": {"name": "CodeGuardian", "informationUri": "https://local"}},
      "results": [{
         "ruleId": f.rule_id,
         "message": {"text": f"{f.name} | {f.cwe} {f.owasp} | conf={round(f.confidence,2)}"},
         "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": f.file},
              "region": {"startLine": f.line}
            }
         }],
         "properties": {"severity": f.severity, "confidence": f.confidence}
      } for f in findings]
    }]
    sarif = {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":runs}
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
'@ | Set-Content engine\reporters\sarif_exporter.py -Encoding UTF8

# --- reporters: html ---
@'
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
'@ | Set-Content engine\reporters\html_reporter.py -Encoding UTF8

# --- rules/python.yml ---
@'
rules:
  - id: PY-CMDI-001
    name: "Command Injection via subprocess(shell=True)"
    pattern: "(?m)subprocess\\.(run|Popen|call)\\(.*shell\\s*=\\s*True"
    cwe: "CWE-78"
    owasp: "A03:2021-Injection"
    severity: "HIGH"
    confidence: 0.9
    why: "shell=True with untrusted input enables command execution."
    fix:
      type: "replace"
      message: "Avoid shell=True. Use list argv and shlex.quote on inputs."
      replace_hint: "shell=False"

  - id: PY-DESER-001
    name: "Insecure deserialization via pickle.load/loads"
    pattern: "(?m)pickle\\.(loads|load)\\("
    cwe: "CWE-502"
    owasp: "A08:2021-Software and Data Integrity Failures"
    severity: "HIGH"
    confidence: 0.85
    why: "Untrusted pickle can execute arbitrary code."
    fix:
      type: "suggest"
      message: "Avoid pickle for untrusted data; prefer json or safer formats."
'@ | Set-Content rules\python.yml -Encoding UTF8

# --- rules/java.yml ---
@'
rules:
  - id: JAVA-SQLI-001
    name: "SQL Injection via string concatenation"
    pattern: "(?s)(Statement\\s+\\w+|createStatement\\(\\)).*\".*\"\\s*\\+\\s*\\w+"
    cwe: "CWE-89"
    owasp: "A03:2021-Injection"
    severity: "HIGH"
    confidence: 0.8
    why: "Concatenating user input into SQL enables injection."
    fix:
      type: "suggest"
      message: "Use PreparedStatement with parameters."

  - id: JAVA-CMDI-001
    name: "Command exec via Runtime.exec"
    pattern: "(?m)Runtime\\.getRuntime\\(\\)\\.exec\\("
    cwe: "CWE-78"
    owasp: "A03:2021-Injection"
    severity: "HIGH"
    confidence: 0.8
    why: "Executing commands with tainted args can lead to RCE."
    fix:
      type: "suggest"
      message: "Validate/escape arguments or avoid shell execution."
'@ | Set-Content rules\java.yml -Encoding UTF8

# --- rules/cpp.yml ---
@'
rules:
  - id: CPP-BO-STRCPY
    name: "Unsafe strcpy/sprintf/gets (buffer overflow risk)"
    pattern: "(?m)\\b(strcpy|sprintf|gets)\\s*\\("
    cwe: "CWE-120"
    owasp: "—"
    severity: "CRITICAL"
    confidence: 0.9
    why: "Unbounded copy into fixed buffers can overflow."
    fix:
      type: "suggest"
      message: "Use strncpy/snprintf with bounds or safer wrappers."

  - id: CPP-FMT-001
    name: "Format string vulnerability"
    pattern: "(?m)printf\\s*\\(\\s*\\w+\\s*\\)"
    cwe: "CWE-134"
    owasp: "—"
    severity: "HIGH"
    confidence: 0.75
    why: "User-controlled format strings can lead to memory disclosure/RCE."
    fix:
      type: "suggest"
      message: "Use constant format string; never pass user input as format."
'@ | Set-Content rules\cpp.yml -Encoding UTF8

# --- rules/csharp.yml ---
@'
rules:
  - id: CS-SQLI-001
    name: "SQL Injection via string concatenation"
    pattern: "(?s)Sql(Command|DataAdapter)\\s*\\(\\s*\".*\"\\s*\\+\\s*\\w+"
    cwe: "CWE-89"
    owasp: "A03:2021-Injection"
    severity: "HIGH"
    confidence: 0.8
    why: "String-built SQL with user input enables injection."
    fix:
      type: "suggest"
      message: "Use parameterized queries (SqlParameter)."

  - id: CS-DESER-001
    name: "Insecure deserialization (BinaryFormatter)"
    pattern: "(?m)new\\s+BinaryFormatter\\s*\\("
    cwe: "CWE-502"
    owasp: "A08:2021-Software and Data Integrity Failures"
    severity: "HIGH"
    confidence: 0.8
    why: "BinaryFormatter is unsafe with untrusted input."
    fix:
      type: "suggest"
      message: "Use safe serializers (System.Text.Json/DataContractJsonSerializer)."
'@ | Set-Content rules\csharp.yml -Encoding UTF8

# --- rules/php.yml ---
@'
rules:
  - id: PHP-SQLI-001
    name: "SQL Injection (mysqli_query with concat)"
    pattern: "(?s)mysqli_query\\s*\\(\\s*\\$\\w+\\s*,\\s*\".*\"\\s*\\.\\s*\\$\\w+"
    cwe: "CWE-89"
    owasp: "A03:2021-Injection"
    severity: "HIGH"
    confidence: 0.85
    why: "Concatenating user input into SQL enables injection."
    fix:
      type: "suggest"
      message: "Use prepared statements (PDO::prepare/execute)."

  - id: PHP-XSS-001
    name: "Reflected XSS via echo of user input"
    pattern: "(?m)echo\\s*\\$\\w+\\s*;|print\\s*\\$\\w+\\s*;"
    cwe: "CWE-79"
    owasp: "A03:2021-Injection"
    severity: "MEDIUM"
    confidence: 0.75
    why: "Echoing unsanitized input can execute JS in the browser."
    fix:
      type: "suggest"
      message: "Escape/encode output (htmlspecialchars) or validate inputs."
'@ | Set-Content rules\php.yml -Encoding UTF8

# --- demo: vulnerable_py/app.py ---
@'
import subprocess, pickle
user = input("cmd? ")
subprocess.run(user, shell=True)  # vuln: PY-CMDI-001
def load(x): return pickle.loads(x)  # vuln: PY-DESER-001
'@ | Set-Content demos\vulnerable_py\app.py -Encoding UTF8

# --- demo: vulnerable_java/App.java ---
@'
import java.sql.*;
class App {
  public static void main(String[] args) throws Exception {
    String uid = args.length>0 ? args[0] : "1";
    Connection c = DriverManager.getConnection("jdbc:demo","u","p");
    Statement st = c.createStatement();
    ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id=" + uid); // JAVA-SQLI-001
    Runtime.getRuntime().exec("cmd /c " + uid); // JAVA-CMDI-001
  }
}
'@ | Set-Content demos\vulnerable_java\App.java -Encoding UTF8

# --- demo: vulnerable_php/index.php ---
@'
<?php
  $name = $_GET["name"]; // user input
  echo $name; // PHP-XSS-001
  $sql = "SELECT * FROM users WHERE id=" . $_GET["id"]; // PHP-SQLI-001
  mysqli_query($conn, $sql);
?>
'@ | Set-Content demos\vulnerable_php\index.php -Encoding UTF8

Write-Host "✅ Bootstrap complete."
