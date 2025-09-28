# Enhanced Zenodo normalization: deep folder scan, metadata extraction, deduplication
import argparse, csv, json, pathlib

LANG_EXT = {
    "python": ".py",
    "java": ".java",
    "c": ".c",
    "c++": ".cpp",
    "cpp": ".cpp",
    "php": ".php",
    "javascript": ".js",
    "ruby": ".rb",
    "go": ".go",
    "csharp": ".cs",
    "typescript": ".ts",
}
CODE_COLS = ["code", "func", "source_code", "snippet", "content", "vul_code", "vulnerable_code"]
LABEL_COLS = ["label", "target", "is_vuln", "is_vulnerable", "vulnerable"]
CWE_COLS = ["cwe", "cwe_id", "cweid", "cwe_label", "cwe_name"]


def detect_col(row, candidates):
    for k in candidates:
        if k in row:
            return k
    return None


def norm_lang_from_filename(fname: str):
    base = pathlib.Path(fname).stem.lower()
    mappings = {
        "python": "python",
        "java": "java",
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "php": "php",
        "javascript": "javascript",
        "js": "javascript",
        "ruby": "ruby",
        "go": "go",
        "csharp": "csharp",
        "cs": "csharp",
        "typescript": "typescript",
        "ts": "typescript",
    }
    for key, lang in mappings.items():
        if key in base:
            return lang
    return None


def process_csv_file(csv_path, files_dir, limit=0, start_cnt=0):
    records = []
    cnt = start_cnt
    with open(csv_path, "r", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        code_col = label_col = cwe_col = None
        for row in rdr:
            if code_col is None:
                code_col = detect_col(row, CODE_COLS)
            if label_col is None:
                label_col = detect_col(row, LABEL_COLS)
            if cwe_col is None:
                cwe_col = detect_col(row, CWE_COLS)
            code = (row.get(code_col) or "").strip()
            if not code:
                continue
            label = row.get(label_col)
            try:
                is_vuln = (
                    1
                    if str(label).strip() in ("1", "True", "true", "vul", "vulnerable")
                    else 0
                )
            except Exception:
                is_vuln = 0
            cwe = (row.get(cwe_col) or "").strip()
            lang = (
                norm_lang_from_filename(csv_path.name)
                or (
                    row.get("programming_language")
                    or row.get("language")
                    or row.get("lang")
                    or ""
                )
                .strip()
                .lower()
                or "python"
            )
            ext = LANG_EXT.get(lang, ".txt")
            lang_dir = files_dir / lang
            lang_dir.mkdir(parents=True, exist_ok=True)
            out_file = lang_dir / f"sample_{cnt}{ext}"
            out_file.write_text(code, encoding="utf-8")
            labels = (
                [{"line": None, "cwe": cwe}]
                if (is_vuln and cwe)
                else ([{"line": None, "cwe": ""}] if is_vuln else [])
            )
            rec = {
                "path": str(out_file.resolve()),
                "language": lang,
                "labels": labels,
                "is_vuln": is_vuln,
                "size": len(code),
                "lines": len(code.splitlines()),
                "source_file": str(csv_path),
            }
            records.append(rec)
            cnt += 1
            if limit and cnt >= limit:
                break
    return records, cnt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--csv_dir", required=True, help="folder that has raw_python_samples.csv etc."
    )
    ap.add_argument("--out_root", default="datasets/normalized/zenodo")
    ap.add_argument("--limit", type=int, default=0, help="optional cap for quick runs")
    args = ap.parse_args()

    in_dir = pathlib.Path(args.csv_dir)
    out_root = pathlib.Path(args.out_root)
    files_dir = out_root / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    gt = out_root / "ground_truth.json"

    all_records = []
    cnt = 0
    for path in in_dir.rglob("*.csv"):
        if path.is_file():
            recs, cnt = process_csv_file(path, files_dir, args.limit, cnt)
            all_records.extend(recs)
            if args.limit and cnt >= args.limit:
                break

    # Deduplicate by path
    unique_records = {rec["path"]: rec for rec in all_records}
    with gt.open("w", encoding="utf-8") as wf:
        json.dump(list(unique_records.values()), wf, ensure_ascii=False, indent=2)
    print(f"✅ Wrote {gt}  (samples={len(unique_records)})")


if __name__ == "__main__":
    main()
