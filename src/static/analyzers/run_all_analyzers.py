#!/usr/bin/env python3
"""
Runner script to execute multi-language analysis across a directory and write combined JSON output.
"""
import json
import shutil
import sys
from pathlib import Path
from datetime import datetime, timezone

from .multi_analyzer import MultiLanguageAnalyzer


def check_tools():
    # Basic PATH-based checks
    tools = {
        "bandit": shutil.which("bandit"),
        "cppcheck": shutil.which("cppcheck"),
        "gosec": shutil.which("gosec"),
        "spotbugs": shutil.which("spotbugs"),
        "phpcs": shutil.which("phpcs"),
        "eslint": shutil.which("eslint"),
    }

    # Allow explicit CPPCHECK_PATH env var for Windows users who installed cppcheck
    cpp_env = None
    try:
        import os

        cpp_env = os.environ.get("CPPCHECK_PATH")
    except Exception:
        cpp_env = None

    if cpp_env:
        cpp_path = Path(cpp_env)
        if cpp_path.exists():
            tools["cppcheck"] = str(cpp_path)

    # If cppcheck still not found, probe common Windows install locations
    if not tools.get("cppcheck"):
        possible = [
            Path("C:/Program Files/cppcheck/cppcheck.exe"),
            Path("C:/Program Files (x86)/cppcheck/cppcheck.exe"),
            Path("C:/tools/cppcheck/cppcheck.exe"),
            Path("C:/cppcheck/cppcheck.exe"),
        ]
        for p in possible:
            if p.exists():
                tools["cppcheck"] = str(p)
                break
    return tools


def main():
    if len(sys.argv) < 2:
        print("Usage: run_all_analyzers.py <target_dir> [output.json]")
        sys.exit(1)

    target = Path(sys.argv[1])

    # Determine output file: if user provided an argument, use it. If it's a directory, write
    # analysis_results.json into that directory. Otherwise default to reports/analysis/analysis_results.json
    if len(sys.argv) > 2:
        candidate = Path(sys.argv[2])
        if candidate.exists() and candidate.is_dir():
            out_file = candidate / "analysis_results.json"
        else:
            # treat as a filename (possibly in a directory that doesn't yet exist)
            out_file = candidate
    else:
        out_dir = Path.cwd() / "reports" / "analysis"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "analysis_results.json"

    if not target.exists():
        print(f"Target {target} does not exist")
        sys.exit(1)

    print(f"Checking analyzer tool availability...")
    tools = check_tools()
    for name, path in tools.items():
        print(f"  {name}: {'FOUND' if path else 'missing'}")

    analyzer = MultiLanguageAnalyzer()

    print(f"Running analysis on {target}...")
    result = analyzer.analyze_directory(str(target), app_name=target.name)

    # Add metadata
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "tool_availability": {k: bool(v) for k, v in tools.items()},
        "result": result,
    }

    # Ensure parent directory exists
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Analysis complete. Results written to {out_file}")


if __name__ == '__main__':
    main()
