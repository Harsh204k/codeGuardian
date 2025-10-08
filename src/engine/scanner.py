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
    function_name: str
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


def scan_files(
    files,
    rules,
    profile: str = "balanced",
    appname: str = "App",
    use_external_analyzers: bool = True,
) -> List[Finding]:
    """
    Main rule-based scanner with optional external analyzer integration.
    - Walks given (language, pathlib.Path) pairs.
    - Applies regex patterns from rules.
    - Creates Finding objects.
    - Optionally applies ML reranker if models/reranker_*.joblib exists.
    - Can integrate external static analysis tools for enhanced detection.
    """
    results: List[Finding] = []

    # confidence profile nudge
    prof_boost = {"strict": +0.05, "balanced": 0.0, "relaxed": -0.05}.get(profile, 0.0)

    # First run the traditional rule-based analysis
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
                function_name = _extract_function_name(text, ln, lang)
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
                        function_name=function_name,
                        cwe=r.get("cwe", ""),
                        owasp=r.get("owasp", "-"),
                        severity=r.get("severity", "MEDIUM"),
                        confidence=conf,
                        why=r.get("why", ""),
                        quickfix=r.get("fix"),
                    )
                )

    # === OPTIONAL: External static analyzers integration ===
    if use_external_analyzers:
        try:
            from .analyzers.multi_analyzer import MultiLanguageAnalyzer

            analyzer = MultiLanguageAnalyzer()

            # Run external analyzers on each file
            for lang, path in files:
                try:
                    analysis_result = analyzer.analyze_file(str(path), appname)
                    external_findings = analyzer._convert_single_file_findings(
                        analysis_result
                    )

                    # Apply profile boost to external findings too
                    for finding in external_findings:
                        finding.confidence = max(
                            0.0, min(1.0, finding.confidence + prof_boost)
                        )

                    results.extend(external_findings)

                except Exception as e:
                    # If external analyzer fails, continue with rule-based results
                    print(f"Warning: External analyzer failed for {path}: {e}")
                    continue

        except ImportError:
            print(
                "Warning: External analyzers not available, using rule-based analysis only"
            )
        except Exception as e:
            print(f"Warning: External analyzer integration failed: {e}")

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


def _extract_function_name(content: str, line_num: int, language: str) -> str:
    """
    Extract the function name containing the given line number.
    """
    lines = content.splitlines()
    if line_num <= 0 or line_num > len(lines):
        return "unknown"

    # Language-specific function patterns
    patterns = {
        "python": [
            r"^\s*def\s+(\w+)\s*\(",
            r"^\s*async\s+def\s+(\w+)\s*\(",
            r"^\s*class\s+(\w+)[:\(]"
        ],
        "java": [
            r"^\s*(?:public|private|protected|static|\s)*\s*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{",
            r"^\s*(?:public|private|protected|\s)*\s*class\s+(\w+)"
        ],
        "php": [
            r"^\s*function\s+(\w+)\s*\(",
            r"^\s*(?:public|private|protected|\s)+function\s+(\w+)\s*\("
        ],
        "cpp": [
            r"^\s*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{",
            r"^\s*(?:class|struct)\s+(\w+)"
        ],
        "csharp": [
            r"^\s*(?:public|private|protected|internal|static|\s)*\s*(?:\w+\s+)*(\w+)\s*\([^)]*\)",
            r"^\s*(?:public|private|protected|internal|\s)*\s*class\s+(\w+)"
        ]
    }

    lang_patterns = patterns.get(language, patterns["java"])  # Default to Java patterns

    # Search backwards from the current line to find function declaration
    for i in range(line_num - 1, max(0, line_num - 50), -1):  # Look back up to 50 lines
        line = lines[i].rstrip()
        if not line or line.strip().startswith(('#', '//', '/*', '*')):  # Skip comments
            continue

        for pattern in lang_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

    return "main" if language in ["java", "cpp", "csharp"] else "module_level"
def scan_files_external_only(
    files, profile: str = "balanced", appname: str = "App"
) -> List[Finding]:
    """
    Scanner that uses only external static analysis tools (no rule-based scanning).
    Useful for comparing external tool results with rule-based results.
    """
    results: List[Finding] = []
    prof_boost = {"strict": +0.05, "balanced": 0.0, "relaxed": -0.05}.get(profile, 0.0)

    try:
        from .analyzers.multi_analyzer import MultiLanguageAnalyzer

        analyzer = MultiLanguageAnalyzer()

        # Run external analyzers on each file
        for lang, path in files:
            try:
                analysis_result = analyzer.analyze_file(str(path), appname)
                external_findings = analyzer._convert_single_file_findings(
                    analysis_result
                )

                # Apply profile boost
                for finding in external_findings:
                    finding.confidence = max(
                        0.0, min(1.0, finding.confidence + prof_boost)
                    )

                results.extend(external_findings)

            except Exception as e:
                print(f"Warning: External analyzer failed for {path}: {e}")
                continue

    except ImportError:
        print("Error: External analyzers not available")
        return []
    except Exception as e:
        print(f"Error: External analyzer integration failed: {e}")
        return []

    # Apply ML reranker if available
    try:
        from .ml_reranker import score_findings  # type: ignore

        threshold = _ml_threshold_from_env()
        results = score_findings(results, threshold=threshold)
    except Exception:
        pass

    return results
