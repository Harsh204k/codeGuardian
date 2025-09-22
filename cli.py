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
        print(f"Scanned {len(files)} files â†’ {len(ranked)} findings. Reports in {out_dir}")

    elif args.cmd == "fix":
        ok = apply_fix_interactive(args.path, args.id, backup=args.backup)
        sys.exit(0 if ok else 2)

    elif args.cmd == "deps":
        run_dependency_audit(args.path, out_dir)

if __name__ == "__main__":
    main()
