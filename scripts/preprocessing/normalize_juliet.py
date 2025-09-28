# Enhanced Juliet normalization: deep folder scan, metadata extraction, deduplication
import argparse, json, re, pathlib

EXT2LANG = {".c": "cpp", ".cpp": "cpp", ".cc": "cpp", ".java": "java", ".cs": "csharp"}
CWE_RX = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def guess_cwe_from_path(p: pathlib.Path) -> str | None:
    s = str(p)
    m = CWE_RX.search(s)
    if m:
        return f"CWE-{m.group(1)}"
    # Also check filename
    name = p.name
    m = CWE_RX.search(name)
    if m:
        return f"CWE-{m.group(1)}"
    return None


def find_vuln_lines(text: str) -> list[int]:
    lines = []
    markers = [
        "POTENTIAL FLAW",
        "FALLTHROUGH",
        "INCIDENTAL",
        "/* FLAW",
        "/* flaw",
        "// FLAW",
        "BAD PRACTICE",
        "/* BAD */",
        "// BAD",
        "/* VULNERABILITY */",
        "// VULNERABILITY",
        "/* SECURITY FLAW */",
        "// SECURITY FLAW",
    ]
    for i, ln in enumerate(text.splitlines(), start=1):
        if any(m in ln for m in markers):
            lines.append(i)
    # fallback: functions named bad()/Bad()
    if not lines:
        for i, ln in enumerate(text.splitlines(), start=1):
            if re.search(r"\b(bad|Bad|vulnerable|Vulnerable)\s*\(", ln):
                lines.append(i)
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--root",
        required=True,
        help="Juliet root containing Cpp/C, Java, Csharp folders",
    )
    ap.add_argument("--out", default="datasets/normalized/juliet/ground_truth.json")
    ap.add_argument(
        "--limit", type=int, default=0, help="Optional limit for quick runs"
    )
    args = ap.parse_args()

    outp = pathlib.Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)

    root = pathlib.Path(args.root)
    records = []
    n = pos = 0

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        lang = EXT2LANG.get(p.suffix.lower())
        if not lang:
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        cwe = guess_cwe_from_path(p) or ""
        vuln_lines = find_vuln_lines(txt)
        is_vuln = 1 if vuln_lines else (1 if "bad" in p.stem.lower() else 0)
        labels = [{"line": ln, "cwe": cwe or ""} for ln in vuln_lines] or (
            [{"line": None, "cwe": cwe or ""}] if is_vuln else []
        )
        rec = {
            "path": str(p.resolve()),
            "language": lang,
            "labels": labels,
            "is_vuln": is_vuln,
            "size": len(txt),
            "lines": len(txt.splitlines()),
            "source_file": str(p),
        }
        records.append(rec)
        n += 1
        pos += is_vuln
        if args.limit and n >= args.limit:
            break

    # Deduplicate by path
    unique_records = {rec["path"]: rec for rec in records}
    with outp.open("w", encoding="utf-8") as wf:
        json.dump(list(unique_records.values()), wf, ensure_ascii=False, indent=2)
    print(f"✅ Wrote {outp}  (files={len(unique_records)}, vuln_files≈{pos})")


if __name__ == "__main__":
    main()
