import os
import re
import uuid
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class Finding:
    id: str
    app: str
    language: str
    rule_id: str
    name: str
    file: str
    line: int
    snippet: str
    cwe: str
    owasp: str
    severity: str
    confidence: float
    why: str
    quickfix: Optional[dict]


def _iter_matches(content: str, pattern: str):
    """
    Yield 1-based line numbers for each regex match in content.
    """
    rx = re.compile(pattern, re.MULTILINE | re.DOTALL)
    for m in rx.finditer(content):
        # count newlines before match.start()
        line = content.count("\n", 0, m.start()) + 1
        yield line


def _ml_threshold_from_env() -> float:
    """
    Read optional ML threshold from env (CG_ML_THRESHOLD), default 0.35.
    """
    try:
        return float(os.environ.get("CG_ML_THRESHOLD", "0.35"))
    except Exception:
        return 0.35


def scan_files(files, rules, profile: str = "balanced", appname: str = "App") -> List[Finding]:
    """
    Main rule-based scanner.
    - Walks given (language, pathlib.Path) pairs.
    - Applies regex patterns from rules.
    - Creates Finding objects.
    - Optionally applies ML reranker if models/reranker_*.joblib exists.
    """
    results: List[Finding] = []

    # confidence profile nudge
    prof_boost = {"strict": +0.05, "balanced": 0.0, "relaxed": -0.05}.get(profile, 0.0)

    for lang, path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            # unreadable file: skip
            continue

        lines = text.splitlines()

        for r in rules:
            # rules_loader may normalize to 'language' (single) or already expand per-language.
            if r.get("language") and r["language"] != lang:
                continue

            pattern = r.get("pattern")
            if not pattern:
                # some loaders expand 'patterns' into multiple rule entries; skip if none
                continue

            for ln in _iter_matches(text, pattern):
                fid = str(uuid.uuid4())[:8]
                snippet = lines[ln - 1][:240] if 0 <= ln - 1 < len(lines) else ""
                base_conf = float(r.get("confidence", 0.7))
                conf = max(0.0, min(1.0, base_conf + prof_boost))

                results.append(
                    Finding(
                        id=f"{r.get('id','RULE')}-{fid}",
                        app=appname,
                        language=lang,
                        rule_id=r.get("id", "RULE"),
                        name=r.get("name", "Rule Match"),
                        file=str(path),
                        line=int(ln),
                        snippet=snippet,
                        cwe=r.get("cwe", ""),
                        owasp=r.get("owasp", "-"),
                        severity=r.get("severity", "MEDIUM"),
                        confidence=conf,
                        why=r.get("why", ""),
                        quickfix=r.get("fix"),
                    )
                )

    # === OPTIONAL: ML reranker (filters/reranks findings) ===
    # If models/reranker_java.joblib (or generic) exists and engine/ml_reranker.py is present,
    # we call it. If anything is missing, we fail open (return raw rule results).
    try:
        from .ml_reranker import score_findings  # type: ignore

        threshold = _ml_threshold_from_env()
        results = score_findings(results, threshold=threshold)
    except Exception:
        # No model / no module / any runtime issue -> keep original results
        pass

    return results
