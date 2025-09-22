import argparse, json, time, pathlib, math, re
from .walker import collect_files
from .rules_loader import load_rules
from .scanner import scan_files
from .reporters.sarif_exporter import export_sarif
from urllib.parse import unquote

import os, re
def _canon(p: str) -> str:
    if not p:
        return ""
    p = re.sub(r"^file:/+","", p)   # drop file:///
    p = unquote(p)                  # <= decode %20 etc.
    p = p.replace("/", "\\")
    try:
        p = str(pathlib.Path(p).resolve(strict=False))
    except Exception:
        p = os.path.abspath(p)
    return p.lower()


def load_gt(path):
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        yield json.loads(line)

def k_loc_of_files(files):
    total_lines = 0
    for _, p in files:
        try:
            total_lines += len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
        except Exception:
            pass
    return max(1, total_lines) / 1000.0

def cwe_from_message(msg: str):
    m = re.search(r"(CWE-\d+)", msg or "")
    return m.group(1) if m else ""

def index_preds_sarif(sarif_path):
    p = pathlib.Path(sarif_path)
    if not p.exists():
        return {}

    data = json.loads(p.read_text(encoding="utf-8"))
    preds: dict[str, list[dict]] = {}

    # Helper to resolve a URI string using originalUriBaseIds (if present)
    def resolve_uri(raw_uri: str, uri_base_id: str | None, run: dict) -> str:
        if not raw_uri:
            return ""
        base_ids = (run.get("originalUriBaseIds") or {})
        if uri_base_id and uri_base_id in base_ids:
            base_uri = (base_ids[uri_base_id] or {}).get("uri") or ""
            if base_uri and not re.match(r"^[a-zA-Z]:[\\/]", raw_uri) and not raw_uri.startswith("file:"):
                # join base + relative
                sep = "/" if not base_uri.endswith(("/", "\\")) else ""
                raw_uri = f"{base_uri}{sep}{raw_uri}"
        return raw_uri

    for run in data.get("runs", []):
        artifacts = run.get("artifacts") or []
        for res in run.get("results", []):
            msg = (res.get("message") or {}).get("text") or ""
            props = res.get("properties") or {}
            cwe = props.get("cwe") or cwe_from_message(msg) or ""

            locs = res.get("locations") or []
            for loc in locs:
                pl = loc.get("physicalLocation") or {}
                art = pl.get("artifactLocation") or {}

                # Prefer explicit uri; fall back to artifact index if present
                uri = art.get("uri") or ""
                if not uri and "index" in art:
                    try:
                        idx = int(art["index"])
                        uri = ((artifacts[idx] or {}).get("location") or {}).get("uri") or ""
                    except Exception:
                        uri = ""

                # Resolve using base ID if provided
                uri = resolve_uri(uri, art.get("uriBaseId"), run)
                uri = _canon(uri)

                region = pl.get("region") or {}
                line = int(region.get("startLine") or 0)

                preds.setdefault(uri, []).append({"line": line, "cwe": cwe})

    return preds


def evaluate(gt_path, results_sarif, line_window=5):
    gt = list(load_gt(gt_path))
    preds = index_preds_sarif(results_sarif)

    TP = FP = FN = 0
    TP_cwe = FP_cwe = FN_cwe = 0

    for rec in gt:
        uri = _canon(rec["path"])
        gold = rec.get("labels", [])
        predicted = preds.get(uri, [])

        # Non-vuln file in GT → any prediction counts as FP in both regimes
        if not rec.get("is_vuln", 0):
            FP += len(predicted)
            FP_cwe += len(predicted)
            continue

        # ---------- detection-only (ignore CWE) ----------
        matched = [False] * len(predicted)
        for gl in gold:
            gline = gl.get("line")
            found = False
            for i, p in enumerate(predicted):
                if matched[i]:
                    continue
                pline = int(p.get("line") or 0)
                line_ok = True if gline is None or pline == 0 else abs(pline - int(gline)) <= line_window
                if line_ok:
                    matched[i] = True
                    TP += 1
                    found = True
                    break
            if not found:
                FN += 1
        FP += matched.count(False)

        # ---------- CWE-strict (require CWE match when GT has one) ----------
        matched_c = [False] * len(predicted)
        for gl in gold:
            gline = gl.get("line")
            gcwe = (gl.get("cwe") or "").strip()
            found = False
            for i, p in enumerate(predicted):
                if matched_c[i]:
                    continue
                pline = int(p.get("line") or 0)
                line_ok = True if gline is None or pline == 0 else abs(pline - int(gline)) <= line_window
                cwe_ok = (not gcwe) or (p.get("cwe") == gcwe)
                if line_ok and cwe_ok:
                    matched_c[i] = True
                    TP_cwe += 1
                    found = True
                    break
            if not found:
                FN_cwe += 1
        FP_cwe += matched_c.count(False)

    def _prf(tp, fp, fn):
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return precision, recall, f1

    precision, recall, f1 = _prf(TP, FP, FN)
    precision_cwe, recall_cwe, f1_cwe = _prf(TP_cwe, FP_cwe, FN_cwe)

    return {
        "TP": TP, "FP": FP, "FN": FN,
        "precision": precision, "recall": recall, "f1": f1,
        "TP_cwe": TP_cwe, "FP_cwe": FP_cwe, "FN_cwe": FN_cwe,
        "precision_cwe": precision_cwe, "recall_cwe": recall_cwe, "f1_cwe": f1_cwe,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", required=True, help="ground_truth.jsonl")
    ap.add_argument("--scan-path", help="(recommended) scan this path now for timing & SARIF")
    ap.add_argument("--langs", default="auto")
    ap.add_argument("--out", default="report")
    ap.add_argument("--line-window", type=int, default=5)
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = out_dir / "results.sarif"

    if args.scan_path:
        files = collect_files(args.scan_path, args.langs)
        rules = load_rules(args.langs)
        t0 = time.time()
        findings = scan_files(files, rules, profile="balanced", appname="EvalRun")
        dt = (time.time()-t0)
        export_sarif(findings, sarif_path)
        ms_per_kloc = (dt*1000)/k_loc_of_files(files)
    else:
        ms_per_kloc = None

    metrics = evaluate(args.gt, sarif_path, args.line_window)
    if ms_per_kloc is not None: metrics["ms_per_kloc"] = ms_per_kloc
    (out_dir/"metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("== EVAL ==")
    print(json.dumps(metrics, indent=2))
    print(f"Wrote {out_dir/'metrics.json'}")

if __name__ == "__main__":
    main()
