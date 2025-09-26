# CodeGuardian — Static Analysis Master Guide

This single document consolidates the project's static analysis implementation, setup, usage, test results, and troubleshooting. It merges the implementation summary, setup instructions, and test notes into one reference for developers and CI engineers.

## Overview

CodeGuardian provides production-ready static analysis across 6 languages with a unified JSON output format and practical fallbacks when external tools are unavailable. The implementation is complete and tested against demo vulnerable samples.

Supported languages: Java, Python, C/C++, PHP, JavaScript/TypeScript, and Go.

This document contains:

- Per-language analyzer details
- Recommended lightweight tools
- Installation and CI guidance
- Unified JSON schema used by analyzers
- Usage examples and runner instructions
- Test results and troubleshooting notes

## Per-language analyzers & tools

Each analyzer is implemented under `src/engine/analyzers/` and returns findings in a consistent JSON schema.

- Java — SpotBugs

  - File: `src/engine/analyzers/java_analyzer.py`
  - Tool: SpotBugs
  - Detects: SQLi (CWE-89), XSS (CWE-79), command injection (CWE-78), path traversal (CWE-22), weak crypto (CWE-327), hardcoded credentials (CWE-798)
  - Status: Implemented and tested
- Python — Bandit

  - File: `src/engine/analyzers/python_analyzer.py`
  - Tool: Bandit (pip install bandit)
  - Detects: Hardcoded passwords (CWE-798), SQLi (CWE-89), command injection (CWE-78), unsafe deserialization (CWE-502), eval() (CWE-95), weak RNG (CWE-330)
  - Status: Implemented and tested
- C/C++ — Cppcheck

  - File: `src/engine/analyzers/cpp_analyzer.py`
  - Tool: Cppcheck
  - Detects: Buffer overflows (CWE-125), null pointer deref (CWE-476), memory leaks (CWE-401), use-after-free (CWE-416), double free (CWE-415), uninitialized variables (CWE-457)
  - Status: Implemented and tested
- PHP — PHPCS + Regex fallback

  - File: `src/engine/analyzers/php_analyzer.py`
  - Tool: PHP_CodeSniffer (phpcs) with security rules; regex fallback when missing
  - Detects: SQLi (CWE-89), command injection (CWE-78), XSS (CWE-79), unsafe deserialization (CWE-502), eval() (CWE-95)
  - Status: Implemented and tested
- JavaScript/TypeScript — ESLint + Regex fallback

  - File: `src/engine/analyzers/js_analyzer.py`
  - Tool: ESLint with security plugins; regex fallback when missing
  - Detects: eval() usage (CWE-95), XSS (CWE-79), Regex DoS (CWE-1333), object injection (CWE-502), command injection (CWE-78)
  - Status: Implemented and tested
- Go — Gosec + Regex fallback

  - File: `src/engine/analyzers/go_analyzer.py`
  - Tool: Gosec; regex fallback when missing
  - Detects: Hardcoded creds (CWE-798), SQLi (CWE-89), command injection (CWE-78), weak crypto (CWE-327), TLS issues (CWE-295)
  - Status: Implemented with fallback; gosec recommended for full coverage

## Multi-Language Coordinator

Central hub: `src/engine/analyzers/multi_analyzer.py`

- Responsibilities:
  - Automatic language detection by extension
  - Dynamic analyzer loading
  - Directory-wide recursive analysis
  - Aggregation of per-file results into unified output

Supported file extensions include: `.py`, `.c`, `.cpp`, `.h`, `.php`, `.js`, `.jsx`, `.ts`, `.tsx`, `.go`, `.java`.

## Unified JSON output

All analyzers return a consistent JSON structure. The canonical fields include:

Top-level:

- `schema_version`: "1.0"
- `language`: language name
- `file`: analyzed file path
- `analyzer`: tool name or `tool/regex-fallback`
- `findings_count`: integer
- `findings`: array of finding objects

Finding object keys (canonical):

- `id`: unique finding id (string)
- `rule_id`: tool-specific rule id
- `vuln`: vulnerability short name
- `file`: path to file
- `line`: line number (integer) when available
- `cwe`: CWE identifier (e.g., `CWE-89`)
- `severity`: `HIGH|MEDIUM|LOW`
- `confidence`: 0.0-1.0 float
- `language`: language name
- `analyzer`: tool name
- `snippet`: code snippet (optional)
- `raw`: raw tool payload / metadata (optional)

Example (single finding):

```json
{
  "id": "PY-B404-0001",
  "rule_id": "B404",
  "vuln": "Insecure use of yaml.load",
  "file": "demos/vulnerable_py/app.py",
  "line": 42,
  "cwe": "CWE-502",
  "severity": "HIGH",
  "confidence": 0.9,
  "language": "python",
  "analyzer": "bandit"
}
```

## Installation & Setup

The project supports installations on Windows, macOS, and Linux. Installing the recommended primary tools yields the best detection coverage; when tools are missing, analyzers fall back to regex-based detection.

### Windows / PowerShell (summary)

- Bandit: `pip install bandit`
- Cppcheck: `choco install cppcheck -y` or download from cppcheck site
- SpotBugs: download from https://spotbugs.github.io/ and add to PATH (or set `SPOTBUGS_HOME`)
- PHPCS: `composer global require "squizlabs/php_codesniffer"` and add Composer global bin to PATH
- ESLint: `npm install -g eslint eslint-plugin-security`
- Gosec: `go install github.com/securego/gosec/v2/cmd/gosec@latest`

### macOS / Linux (summary)

- Bandit: `pip3 install bandit`
- Cppcheck: `brew install cppcheck` (macOS) or `sudo apt-get install cppcheck` (Ubuntu)
- SpotBugs: download binary and add to PATH
- PHPCS: `composer global require "squizlabs/php_codesniffer"`
- ESLint: `npm install -g eslint eslint-plugin-security`
- Gosec: `GO111MODULE=on go install github.com/securego/gosec/v2/cmd/gosec@latest`

### Quick smoke tests

Run the following to confirm installation:

- `bandit -V`
- `cppcheck --version`
- `spotbugs -version`
- `phpcs --version`
- `eslint -v`
- `gosec version`

## Usage

Single file:

```powershell
# Python
py src\engine\analyzers\python_analyzer.py demos\vulnerable_py\app.py AppName

# Any supported file via multi analyzer
py src\engine\analyzers\multi_analyzer.py path\to\file.ext AppName
```

Directory analysis:

```powershell
py src\engine\analyzers\multi_analyzer.py demos MyApp
```

There is also a runner script `src/engine/analyzers/run_all_analyzers.py` which checks tool availability and writes an aggregated JSON (`analysis_resul`

`.json`) with metadata such as `generated_at` (UTC), `tool_availability`, and per-language counts.

## CI Integration

The repository includes a GitHub Actions workflow to install primary analyzers and run the runner in CI. For reliable CI runs, ensure the workflow installs system packages (cppcheck, go, node) and global tools (phpcs, eslint, gosec, bandit).

If tools cannot be installed in CI, the analyzers will run in regex-fallback mode; the runner records `tool_availability` to make results explicit.

## Test Results (summary)

Testing with `demos/` vulnerable samples produced the following aggregated findings (local run):

- Python (Bandit): 11 findings
- C++ (Cppcheck): 6 findings
- PHP (PHPCS/Regex): 4 findings
- JavaScript (ESLint/Regex): 1 finding
- Go (Gosec): 0 findings locally (gosec may be missing)

Total local findings across demos: 22

Unit tests (`tests/unit/test_analyzers.py`) validate per-analyzer output format and will fall back to `demos/` samples when `tests/fixtures` is missing.

## Troubleshooting

- Tool not found: install the listed tool and ensure it's on PATH. The analyzers will indicate fallback if the tool is missing (e.g., `analyzer: "bandit/regex-fallback"`).
- No findings: confirm file contains vulnerable patterns and that primary tool is installed. If using the regex fallback, ensure patterns match the file.
- Pytest config BOM: if pytest fails due to BOM in `pytest.ini`, re-save the file without BOM or use the included test runner `scripts/run_unit_tests.py` which sets up `src` on `sys.path`.

## Files & Locations

Key files:

- `src/engine/analyzers/multi_analyzer.py` — central coordinator
- `src/engine/analyzers/python_analyzer.py` — Bandit integration
- `src/engine/analyzers/java_analyzer.py` — SpotBugs integration
- `src/engine/analyzers/cpp_analyzer.py` — Cppcheck integration
- `src/engine/analyzers/php_analyzer.py` — PHPCS + regex fallback
- `src/engine/analyzers/js_analyzer.py` — ESLint + regex fallback
- `src/engine/analyzers/go_analyzer.py` — Gosec + regex fallback
- `src/engine/analyzers/run_all_analyzers.py` — runner that aggregates results
- `docs/STATIC_ANALYSIS_SETUP.md` — original setup guide (kept for historic reference)

## Conclusion

This master guide consolidates the full static analysis implementation and operational guidance for CodeGuardian. The project delivers consistent JSON output across languages, industry-standard tool support, fallback regex analysis, CI integration, and supporting documentation.

If you'd like, I can:

- Add a short README snippet at the repo root linking to this master guide
- Open a PR with the merged doc and run the CI workflow in a test branch
- Expand the CI workflow to selectively cache tool installs for faster runs

---

Generated by merging project analysis docs on {date}
