# Enhanced DiverseVul normalization: deep folder scan, multiple formats, metadata extraction
import argparse, json, pathlib, csv

LANG_EXT = {
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "java": ".java",
    "python": ".py",
    "javascript": ".js",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
}


def detect_language_from_ext(path):
    ext = pathlib.Path(path).suffix.lower()
    for lang, lang_ext in LANG_EXT.items():
        if ext == lang_ext:
            return lang
    return "unknown"


def detect_language(item, fallback_path=None):
    lang_fields = ["lang", "language", "programming_language"]
    for field in lang_fields:
        lang = item.get(field, "").strip().lower()
        if lang:
            return lang
    if fallback_path:
        return detect_language_from_ext(fallback_path)
    code = item.get("func", "").lower()
    if "import java" in code or "public class" in code:
        return "java"
    elif "#include" in code or "int main" in code:
        return "c"
    elif "def " in code and "import" in code:
        return "python"
    elif "function" in code and ("var " in code or "const " in code):
        return "javascript"
    return "unknown"


def process_json_file(json_path, files_dir, limit=0, start_cnt=0):
    records = []
    cnt = start_cnt
    vuln_count = safe_count = 0
    with open(json_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            code = item.get("func", "").strip()
            if not code:
                continue
            target = item.get("target", 0)
            is_vuln = 1 if target == 1 else 0
            lang = detect_language(item, fallback_path=json_path)
            cwe = item.get("cwe", [])
            if isinstance(cwe, list):
                cwe = ",".join(cwe)
            else:
                cwe = str(cwe)
            ext = LANG_EXT.get(lang, ".txt")
            lang_dir = files_dir / lang
            lang_dir.mkdir(exist_ok=True)
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
                "source_file": str(json_path),
            }
            records.append(rec)
            cnt += 1
            if is_vuln:
                vuln_count += 1
            else:
                safe_count += 1
            if limit and cnt >= limit:
                break
    return records, cnt, vuln_count, safe_count


def process_csv_file(csv_path, files_dir, limit=0, start_cnt=0):
    records = []
    cnt = start_cnt
    vuln_count = safe_count = 0
    with open(csv_path, "r", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            code = row.get("code", "").strip()
            if not code:
                continue
            lang = row.get("language") or detect_language_from_ext(csv_path)
            cwe = row.get("cwe", "")
            if isinstance(cwe, list):
                cwe = ",".join(cwe)
            else:
                cwe = str(cwe)
            is_vuln = int(row.get("target", 0))
            ext = LANG_EXT.get(lang, ".txt")
            lang_dir = files_dir / lang
            lang_dir.mkdir(exist_ok=True)
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
            if is_vuln:
                vuln_count += 1
            else:
                safe_count += 1
            if limit and cnt >= limit:
                break
    return records, cnt, vuln_count, safe_count


def process_code_file(code_path, files_dir, limit=0, start_cnt=0):
    code = pathlib.Path(code_path).read_text(encoding="utf-8", errors="ignore")
    lang = detect_language_from_ext(code_path)
    ext = LANG_EXT.get(lang, ".txt")
    lang_dir = files_dir / lang
    lang_dir.mkdir(exist_ok=True)
    out_file = lang_dir / f"sample_{start_cnt}{ext}"
    out_file.write_text(code, encoding="utf-8")
    rec = {
        "path": str(out_file.resolve()),
        "language": lang,
        "labels": [],
        "is_vuln": 0,
        "size": len(code),
        "lines": len(code.splitlines()),
        "source_file": str(code_path),
    }
    return [rec], start_cnt + 1, 0, 1


def main():
    ap = argparse.ArgumentParser(
        description="Deeply normalize DiverseVul dataset folder"
    )
    ap.add_argument(
        "--input_dir", default="datasets/diversevul", help="Input DiverseVul folder"
    )
    ap.add_argument("--out", default="datasets/normalized/diversevul/ground_truth.json")
    ap.add_argument(
        "--limit", type=int, default=0, help="Optional limit for quick testing"
    )
    args = ap.parse_args()

    input_dir = pathlib.Path(args.input_dir)
    out_root = pathlib.Path(args.out).parent
    files_dir = out_root / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    gt_file = pathlib.Path(args.out)

    all_records = []
    cnt = vuln_count = safe_count = 0
    for path in input_dir.rglob("*"):
        if path.is_file():
            if path.suffix == ".json":
                recs, cnt, v, s = process_json_file(path, files_dir, args.limit, cnt)
                all_records.extend(recs)
                vuln_count += v
                safe_count += s
            elif path.suffix == ".csv":
                recs, cnt, v, s = process_csv_file(path, files_dir, args.limit, cnt)
                all_records.extend(recs)
                vuln_count += v
                safe_count += s
            elif path.suffix in LANG_EXT.values():
                recs, cnt, v, s = process_code_file(path, files_dir, args.limit, cnt)
                all_records.extend(recs)
                safe_count += s
            if args.limit and cnt >= args.limit:
                break

    # Deduplicate by path
    unique_records = {rec["path"]: rec for rec in all_records}
    with gt_file.open("w", encoding="utf-8") as wf:
        json.dump(list(unique_records.values()), wf, ensure_ascii=False, indent=2)
    print(f"✅ Wrote {gt_file} (samples={len(unique_records)})")
    print(f"   Vulnerable: {vuln_count}")
    print(f"   Safe: {safe_count}")
    print(f"   Files created in: {files_dir}")


if __name__ == "__main__":
    main()
