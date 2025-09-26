# Normalize the multi-language CSVs (Python/Java/C/C++/PHP…) into files + ground_truth.jsonl
import argparse, csv, json, pathlib, re, random

LANG_EXT = {
    "python": ".py", "java": ".java", "c": ".c", "c++": ".cpp", "cpp": ".cpp", "php": ".php",
    "javascript": ".js", "ruby": ".rb", "go": ".go"
}
# try common header names
CODE_COLS = ["code","func","source_code","snippet","content","vul_code"]
LABEL_COLS = ["label","target","is_vuln","is_vulnerable","vulnerable"]
CWE_COLS = ["cwe","cwe_id","cweid","cwe_label"]

def detect_col(row, candidates):
    for k in candidates:
        if k in row: return k
    return None

def norm_lang_from_filename(fname: str):
    base = pathlib.Path(fname).stem.lower()
    for key in LANG_EXT:
        if key in base: return key
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv_dir", required=True, help="folder that has raw_python_samples.csv etc.")
    ap.add_argument("--out_root", default="datasets/normalized/zenodo")
    ap.add_argument("--limit", type=int, default=0, help="optional cap for quick runs")
    args = ap.parse_args()

    in_dir = pathlib.Path(args.csv_dir)
    out_root = pathlib.Path(args.out_root)
    files_dir = out_root / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    gt = out_root / "ground_truth.jsonl"

    cnt = 0
    with gt.open("w", encoding="utf-8") as wf:
        for csvf in sorted(in_dir.glob("*.csv")):
            lang_guess = norm_lang_from_filename(csvf.name)
            with csvf.open("r", encoding="utf-8", errors="ignore") as f:
                rdr = csv.DictReader(f)
                code_col = label_col = cwe_col = None
                for row in rdr:
                    if code_col is None: code_col = detect_col(row, CODE_COLS)
                    if label_col is None: label_col = detect_col(row, LABEL_COLS)
                    if cwe_col is None: cwe_col = detect_col(row, CWE_COLS)
                    code = (row.get(code_col) or "").strip()
                    if not code: continue
                    label = row.get(label_col)
                    try:
                        is_vuln = 1 if str(label).strip() in ("1","True","true","vul","vulnerable") else 0
                    except Exception:
                        is_vuln = 0
                    cwe = (row.get(cwe_col) or "").strip()
                    lang = (
                        lang_guess
                        or (row.get("programming_language") or row.get("language") or row.get("lang") or "")
                            .strip().lower()
                        or "python"
                    )

                    ext = LANG_EXT.get(lang, ".txt")
                    out_file = files_dir / lang / f"sample_{cnt}{ext}"
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text(code, encoding="utf-8")
                    labels = [{"line": None, "cwe": cwe}] if (is_vuln and cwe) else ([{"line": None, "cwe": ""}] if is_vuln else [])
                    rec = {"path": str(out_file.resolve()), "language": lang, "labels": labels, "is_vuln": is_vuln}
                    wf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    cnt += 1
                    if args.limit and cnt >= args.limit: break
            print(f"Parsed {csvf.name}")
    print(f"✅ Wrote {gt}  (samples={cnt})")

if __name__ == "__main__":
    main()
