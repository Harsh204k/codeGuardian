"""
Normalization helper for analyzer outputs.

Provides a simple canonicalizer that converts analyzer-specific JSON outputs
into a minimal, consistent schema used by the scanner and downstream tools.

Canonical output schema (per finding):
- id: unique finding id
- rule_id: analyzer rule identifier
- vuln: human-readable vulnerability name
- file: file path
- line: line number (int)
- cwe: CWE identifier (e.g. CWE-89) or "CWE-UNKNOWN"
- severity: LOW/MEDIUM/HIGH
- confidence: 0.0-1.0 float
- language: language string (java, python, cpp, php, javascript, go)
- analyzer: source analyzer string (spotbugs, bandit, cppcheck, phpcs, eslint, gosec)
- snippet: short code snippet (optional)
- raw: original finding dict (optional)

Top-level canonical output:
{
  "schema_version": "1.0",
  "language": "python",
  "file": "path/to/file.py",
  "analyzer": "bandit",
  "findings": [ { ...canonical finding... }, ... ]
}

This module also exposes a CLI to normalize a JSON file (or stdin).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List


CANONICAL_KEYS = [
    "id",
    "rule_id",
    "vuln",
    "file",
    "line",
    "cwe",
    "severity",
    "confidence",
    "language",
    "analyzer",
    "snippet",
    "raw",
]


def _get_field(d: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def normalize_finding(
    f: Dict[str, Any], language_hint: str = None, analyzer_hint: str = None
) -> Dict[str, Any]:
    """Convert a single analyzer finding dict to canonical schema.

    The function tries common field names used in existing analyzers and falls
    back to reasonable defaults.
    """
    # id
    fid = (
        _get_field(f, "id", "finding_id", "uid")
        or f"FINDING-{abs(hash(str(f))) % (10**8)}"
    )

    # rule id
    rule_id = _get_field(f, "rule_id", "rule", "source", "type") or "UNKNOWN"

    # name/vuln
    vuln = _get_field(f, "name", "vuln", "message", "test_name") or rule_id

    # file and line
    file_path = (
        _get_field(f, "file", "filename", "path")
        or _get_field(
            f.get("raw", {}) if isinstance(f.get("raw"), dict) else {}, "file"
        )
        or ""
    )

    # Line may appear as int or string
    line = _get_field(f, "line", "line_number", "start", "line_no") or 0
    try:
        line = int(line)
    except Exception:
        line = 0

    # cwe
    cwe = _get_field(f, "cwe", "CWE", "cwe_id") or "CWE-UNKNOWN"

    # severity
    severity = _get_field(f, "severity", "level", "impact") or "MEDIUM"
    if isinstance(severity, str):
        sev = severity.upper()
        if sev in ("LOW", "MEDIUM", "HIGH"):
            severity = sev
        else:
            # map common numeric or textual values
            try:
                num = float(severity)
                if num >= 0.75:
                    severity = "HIGH"
                elif num >= 0.4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            except Exception:
                severity = "MEDIUM"

    # confidence
    confidence = _get_field(f, "confidence", "conf", "score")
    if confidence is None:
        # try mapping textual confidence
        conf_text = _get_field(f, "confidence_text", "confidence_level", default=None)
        if isinstance(conf_text, str):
            ct = conf_text.lower()
            if ct in ("high", "h"):
                confidence = 0.9
            elif ct in ("medium", "med", "m"):
                confidence = 0.6
            elif ct in ("low", "l"):
                confidence = 0.3
        else:
            # default mapping from severity
            confidence = (
                0.9 if severity == "HIGH" else (0.6 if severity == "MEDIUM" else 0.3)
            )
    else:
        try:
            confidence = float(confidence)
            if confidence > 1:
                # normalize 0-100 -> 0-1
                if confidence > 1 and confidence <= 100:
                    confidence = confidence / 100.0
                elif confidence > 1:
                    confidence = max(0.0, min(confidence, 1.0))
        except Exception:
            confidence = 0.6

    # language and analyzer
    language = language_hint or _get_field(f, "language", "lang") or "unknown"
    analyzer = analyzer_hint or _get_field(f, "analyzer", "tool", "engine") or "unknown"

    # snippet
    snippet = _get_field(f, "snippet", "code", "line_text") or ""

    canonical = {
        "id": str(fid),
        "rule_id": str(rule_id),
        "vuln": str(vuln),
        "file": str(file_path),
        "line": int(line),
        "cwe": str(cwe),
        "severity": str(severity),
        "confidence": float(confidence),
        "language": str(language),
        "analyzer": str(analyzer),
        "snippet": str(snippet),
        "raw": f,
    }

    return canonical


def normalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an analyzer result (full JSON) into top-level canonical form.

    Accepts common analyzer outputs that include keys like:
    - language, file, analyzer, findings (list)
    or fallbacks where the top-level is already a single finding.
    """
    language = result.get("language") or result.get("lang") or "unknown"
    analyzer = result.get("analyzer") or result.get("tool") or "unknown"
    file_path = result.get("file") or ""

    findings_raw = []
    if isinstance(result.get("findings"), list):
        findings_raw = result.get("findings")
    else:
        # some analyzers return a top-level list or results key
        if isinstance(result.get("results"), list):
            findings_raw = result.get("results")
        else:
            # try common fallbacks
            # If result itself looks like a finding
            keys = set(result.keys())
            if {"file", "line", "name"}.issubset(keys) or {"rule_id", "file"}.issubset(
                keys
            ):
                findings_raw = [result]
            else:
                # nothing recognized: maybe top-level is list
                if isinstance(result, list):
                    findings_raw = result
                else:
                    findings_raw = []

    canonical_findings = [
        normalize_finding(f, language_hint=language, analyzer_hint=analyzer)
        for f in findings_raw
    ]

    return {
        "schema_version": "1.0",
        "language": language,
        "file": file_path,
        "analyzer": analyzer,
        "findings": canonical_findings,
    }


def cli_normalize():
    """Simple CLI: read JSON from file (arg1) or stdin and print normalized JSON."""
    if len(sys.argv) >= 2 and sys.argv[1] not in ("-",):
        path = sys.argv[1]
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    normalized = normalize_result(data)
    print(json.dumps(normalized, indent=2))


if __name__ == "__main__":
    cli_normalize()
