import json, pathlib, re, csv
from urllib.parse import unquote


def canon(p: str) -> str:
    p = re.sub(r"^file:/+", "", p or "")
    return (
        str(pathlib.Path(unquote(p)).resolve(strict=False)).lower().replace("/", "\\")
    )


def cwe_from_msg(msg: str):
    m = re.search(r"(CWE-\d+)", msg or "")
    return m.group(1) if m else ""


def load_combined_gt(gt_dir):
    gt = {}
    gt_dir_path = pathlib.Path(gt_dir)
    for gt_file in gt_dir_path.glob("*/ground_truth.json"):
        try:
            with open(gt_file, encoding="utf-8") as f:
                data = json.load(f)
                for o in data:
                    path_lower = o["path"].lower()
                    gt[path_lower] = o  # store the full record with metadata
        except Exception as e:
            print(f"Warning: failed to load {gt_file}: {e}")
    return gt


def index_sarif(sarif_path):
    data = json.loads(pathlib.Path(sarif_path).read_text(encoding="utf-8"))
    hits = []
    for run in data.get("runs", []):
        arts = run.get("artifacts") or []
        for res in run.get("results", []):
            msg = (res.get("message") or {}).get("text", "")
            cwe = (res.get("properties") or {}).get("cwe") or cwe_from_msg(msg)
            for loc in res.get("locations") or []:
                pl = loc.get("physicalLocation") or {}
                art = pl.get("artifactLocation") or {}
                uri = art.get("uri") or ""
                if not uri and "index" in art:
                    try:
                        idx = int(art["index"])
                        uri = ((arts[idx] or {}).get("location") or {}).get("uri") or ""
                    except:
                        pass
                path = canon(uri)
                line = int((pl.get("region") or {}).get("startLine") or 0)
                hits.append(
                    {
                        "path": path,
                        "line": line,
                        "cwe": cwe,
                        "ruleId": res.get("ruleId", ""),
                        "msg": msg,
                    }
                )
    return hits


def read_code(path, center_line, radius=60):
    try:
        lines = (
            pathlib.Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        )
        s = max(0, center_line - 1 - radius)
        e = min(len(lines), center_line - 1 + radius)
        snippet = "\n".join(lines[s:e])
        return lines, snippet
    except:
        return [], ""


def featurize(snippet: str, rule_id: str, cwe: str, metadata: dict):
    lower = snippet.lower()
    feats = {
        "ruleId": rule_id,
        "cwe": cwe,
        "len": len(snippet),
        "plus_count": snippet.count("+"),
        "concat_sql": int(
            (
                "select" in lower
                or "insert" in lower
                or "update" in lower
                or "delete" in lower
            )
            and ("+" in snippet or "concat" in lower)
        ),
        "has_exec": int(
            "runtime.getruntime().exec" in lower or "processbuilder" in lower
        ),
        "has_header": int(
            "addheader" in lower or "setheader" in lower or "sendredirect" in lower
        ),
        "has_getparam": int(
            "getparameter" in lower
            or "getquerystring" in lower
            or "getheader(" in lower
            or "getreader().readline" in lower
        ),
        "has_writer": int(
            "getwriter().print" in lower
            or "getwriter().println" in lower
            or "out.print" in lower
        ),
        "has_md5_sha1": int(
            'messagedigest.getinstance("md5"' in lower
            or 'messagedigest.getinstance("sha1"' in lower
        ),
        "aes_ecb": int('cipher.getinstance("aes/ecb' in lower),
        "path_file": int("new file(" in lower or "paths.get(" in lower),
        "xxe_factory": int(
            "documentbuilderfactory.newinstance(" in lower
            or "saxparserfactory.newinstance(" in lower
            or "xmlinputfactory.newinstance(" in lower
        ),
        "language": metadata.get("language", ""),
        "file_size": metadata.get("size", 0),
        "file_lines": metadata.get("lines", 0),
    }
    return feats


def label_hit(gt_labels, pred_line, line_window=50, pred_cwe=""):
    # 1 if any GT label in window (CWE-agnostic); keep CWE label for analysis
    for lab in gt_labels:
        gline = lab.get("line")
        if (
            gline is None
            or pred_line == 0
            or abs(int(gline) - int(pred_line)) <= line_window
        ):
            return 1
    return 0


def main(gt_dir, sarif_path, out_csv):
    gt = load_combined_gt(gt_dir)
    preds = index_sarif(sarif_path)
    rows = []
    for p in preds:
        path = p["path"]
        line = p["line"]
        cwe = p["cwe"]
        ruleId = p["ruleId"]
        record = gt.get(path)
        if record:
            labels = record.get("labels", [])
            metadata = {k: v for k, v in record.items() if k != "labels"}
        else:
            labels = []
            metadata = {}
        _, snippet = read_code(path, line)
        feats = featurize(snippet, ruleId, cwe, metadata)
        y = label_hit(labels, line, line_window=50, pred_cwe=cwe)
        rows.append({**feats, "y": y})
    cols = list(rows[0].keys()) if rows else []
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"✅ wrote {out_csv} rows={len(rows)}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Build training table from SARIF results and ground truth"
    )
    ap.add_argument(
        "--gt_dir",
        default="datasets/normalized",
        help="Ground truth directory containing dataset subfolders with ground_truth.json (default: datasets/normalized)",
    )
    ap.add_argument(
        "--sarif",
        default="reports/analysis/results.sarif",
        help="SARIF results file (default: reports/analysis/results.sarif)",
    )
    ap.add_argument(
        "--out",
        default="datasets/processed/training_table.csv",
        help="Output CSV file (default: datasets/processed/training_table.csv)",
    )
    args = ap.parse_args()
    main(args.gt_dir, args.sarif, args.out)
