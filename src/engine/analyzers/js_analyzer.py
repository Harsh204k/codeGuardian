#!/usr/bin/env python3
"""
JavaScript static analysis using ESLint with security plugin for vulnerability detection.
Outputs findings in the same format as the main scanner.
"""

import json
import subprocess
import sys
import uuid
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict


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
    quickfix: dict = None


# Mapping from ESLint security rules to CWE numbers
ESLINT_CWE_MAPPING = {
    "security/detect-unsafe-regex": "CWE-1333",
    "security/detect-buffer-noassert": "CWE-125",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-eval-with-expression": "CWE-95",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-non-literal-regexp": "CWE-1333",
    "security/detect-non-literal-require": "CWE-98",
    "security/detect-object-injection": "CWE-502",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-330",
    "security/detect-sql-injection": "CWE-89",
    "security/detect-xss": "CWE-79",
    "no-eval": "CWE-95",
    "no-implied-eval": "CWE-95",
    "no-new-func": "CWE-95",
    "no-script-url": "CWE-79",
    "node/no-deprecated-api": "CWE-477",
}

# Severity mapping
SEVERITY_MAPPING = {2: "HIGH", 1: "MEDIUM", 0: "LOW"}  # error  # warn  # off

# Confidence mapping
CONFIDENCE_MAPPING = {2: 0.9, 1: 0.6, 0: 0.3}  # error  # warn  # off


def run_simple_js_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run a simple regex-based JavaScript security analysis when ESLint is not available.
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

        # Define security patterns for JavaScript
        security_patterns = [
            {
                "pattern": r"\beval\s*\(",
                "name": "Dangerous eval() function",
                "cwe": "CWE-95",
                "severity": "HIGH",
                "message": "Use of eval() can lead to code injection vulnerabilities",
            },
            {
                "pattern": r"new\s+Function\s*\(",
                "name": "Function constructor",
                "cwe": "CWE-95",
                "severity": "HIGH",
                "message": "Function constructor can lead to code injection",
            },
            {
                "pattern": r'setTimeout\s*\(\s*[\'"][^\'")]*[\'"]',
                "name": "setTimeout with string",
                "cwe": "CWE-95",
                "severity": "MEDIUM",
                "message": "setTimeout with string argument can lead to code injection",
            },
            {
                "pattern": r'setInterval\s*\(\s*[\'"][^\'")]*[\'"]',
                "name": "setInterval with string",
                "cwe": "CWE-95",
                "severity": "MEDIUM",
                "message": "setInterval with string argument can lead to code injection",
            },
            {
                "pattern": r"document\.write\s*\(",
                "name": "document.write usage",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "document.write can lead to XSS vulnerabilities",
            },
            {
                "pattern": r"innerHTML\s*=\s*[^;]*\+",
                "name": "innerHTML concatenation",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "Direct concatenation to innerHTML can lead to XSS",
            },
            {
                "pattern": r"outerHTML\s*=\s*[^;]*\+",
                "name": "outerHTML concatenation",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "Direct concatenation to outerHTML can lead to XSS",
            },
            {
                "pattern": r"insertAdjacentHTML\s*\(",
                "name": "insertAdjacentHTML usage",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "insertAdjacentHTML with user input can lead to XSS",
            },
            {
                "pattern": r"location\.href\s*=\s*[^;]*\+",
                "name": "Dynamic location.href",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "Dynamic assignment to location.href can be dangerous",
            },
            {
                "pattern": r"window\.open\s*\([^)]*\+",
                "name": "Dynamic window.open",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "Dynamic window.open can lead to security issues",
            },
            {
                "pattern": r"require\s*\(\s*[^)]*\+",
                "name": "Dynamic require",
                "cwe": "CWE-98",
                "severity": "HIGH",
                "message": "Dynamic require can lead to code injection",
            },
            {
                "pattern": r"child_process\.(exec|spawn|execSync|spawnSync)",
                "name": "Child process execution",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "Child process execution can lead to command injection",
            },
            {
                "pattern": r"fs\.(readFile|writeFile|readFileSync|writeFileSync)\s*\([^)]*\+",
                "name": "Dynamic file operations",
                "cwe": "CWE-22",
                "severity": "HIGH",
                "message": "Dynamic file operations can lead to path traversal",
            },
            {
                "pattern": r"Math\.random\s*\(\s*\)",
                "name": "Weak random number generation",
                "cwe": "CWE-330",
                "severity": "MEDIUM",
                "message": "Math.random() is not cryptographically secure",
            },
            {
                "pattern": r"crypto\.pseudoRandomBytes",
                "name": "Weak crypto function",
                "cwe": "CWE-330",
                "severity": "MEDIUM",
                "message": "pseudoRandomBytes is not cryptographically secure",
            },
            {
                "pattern": r"JSON\.parse\s*\([^)]*\+",
                "name": "Dynamic JSON.parse",
                "cwe": "CWE-502",
                "severity": "MEDIUM",
                "message": "Parsing user-controlled JSON can be dangerous",
            },
            {
                "pattern": r'script:\s*[\'"][^\'")]*javascript:',
                "name": "JavaScript URL scheme",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "JavaScript URL scheme can lead to XSS",
            },
            {
                "pattern": r'href\s*=\s*[\'"][^\'")]*javascript:',
                "name": "JavaScript URL in href",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "JavaScript URLs in href can lead to XSS",
            },
        ]

        for i, line in enumerate(lines, 1):
            for pattern_def in security_patterns:
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    finding = Finding(
                        id=f"JS-REGEX-{str(uuid.uuid4())[:8]}",
                        app=app_name,
                        language="javascript",
                        rule_id=f"JS-{pattern_def['name'].replace(' ', '_').upper()}",
                        name=pattern_def["name"],
                        file=file_path,
                        line=i,
                        snippet=line.strip()[:240],
                        cwe=pattern_def["cwe"],
                        owasp=get_owasp_category(pattern_def["cwe"]),
                        severity=pattern_def["severity"],
                        confidence=0.7,
                        why=pattern_def["message"],
                        quickfix={
                            "type": "suggest",
                            "message": f"Fix: {pattern_def['message']}",
                        },
                    )
                    findings.append(finding)

    except Exception as e:
        print(f"Error in simple JavaScript analysis: {e}", file=sys.stderr)

    return findings


def run_eslint_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run ESLint analysis with security plugin on a JavaScript file.
    Falls back to simple regex analysis if ESLint is not available.
    """
    findings = []

    try:
        # Try to run ESLint with security plugin
        cmd = [
            "npx",
            "eslint",
            "--format",
            "json",
            "--ext",
            ".js,.jsx,.ts,.tsx",
            file_path,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.stdout.strip():
            try:
                eslint_output = json.loads(result.stdout)

                # Process ESLint results
                for file_result in eslint_output:
                    for message in file_result.get("messages", []):
                        rule_id = message.get("ruleId", "UNKNOWN")
                        if (
                            not rule_id
                        ):  # Skip messages without rule ID (syntax errors, etc.)
                            continue

                        msg_text = message.get("message", "Security issue detected")
                        severity_num = message.get("severity", 1)

                        finding = Finding(
                            id=f"JS-{rule_id.replace('/', '-')}-{str(uuid.uuid4())[:8]}",
                            app=app_name,
                            language="javascript",
                            rule_id=f"JS-{rule_id}",
                            name=rule_id.replace("/", " ").replace("-", " ").title(),
                            file=file_path,
                            line=message.get("line", 0),
                            snippet=get_line_snippet(file_path, message.get("line", 0)),
                            cwe=get_cwe_from_rule(rule_id),
                            owasp=get_owasp_category_from_cwe(
                                get_cwe_from_rule(rule_id)
                            ),
                            severity=SEVERITY_MAPPING.get(severity_num, "MEDIUM"),
                            confidence=CONFIDENCE_MAPPING.get(severity_num, 0.6),
                            why=msg_text,
                            quickfix={
                                "type": "suggest",
                                "message": f"Review and fix: {msg_text}",
                            },
                        )
                        findings.append(finding)

            except json.JSONDecodeError:
                print(
                    "Failed to parse ESLint JSON output, falling back to regex analysis",
                    file=sys.stderr,
                )
                return run_simple_js_analysis(file_path, app_name)

    except subprocess.TimeoutExpired:
        print(f"Timeout running ESLint on {file_path}", file=sys.stderr)
        return run_simple_js_analysis(file_path, app_name)
    except FileNotFoundError:
        print("ESLint not found, using fallback regex analysis", file=sys.stderr)
        return run_simple_js_analysis(file_path, app_name)
    except Exception as e:
        print(
            f"Error running ESLint: {e}, falling back to regex analysis",
            file=sys.stderr,
        )
        return run_simple_js_analysis(file_path, app_name)

    return findings


def get_cwe_from_rule(rule_id: str) -> str:
    """Get CWE from ESLint rule ID."""
    if rule_id in ESLINT_CWE_MAPPING:
        return ESLINT_CWE_MAPPING[rule_id]

    # Check for common patterns
    if "eval" in rule_id or "function" in rule_id:
        return "CWE-95"
    elif "xss" in rule_id or "script" in rule_id:
        return "CWE-79"
    elif "sql" in rule_id:
        return "CWE-89"
    elif "command" in rule_id or "child-process" in rule_id:
        return "CWE-78"
    elif "csrf" in rule_id:
        return "CWE-352"
    elif "random" in rule_id:
        return "CWE-330"
    else:
        return "CWE-693"


def get_line_snippet(file_path: str, line_num: int) -> str:
    """Get a snippet of code from the specified line."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if 0 <= line_num - 1 < len(lines):
                return lines[line_num - 1].strip()[:240]
    except Exception:
        pass
    return ""


def get_owasp_category(cwe: str) -> str:
    """Map CWE to OWASP category."""
    injection_cwes = ["CWE-89", "CWE-78", "CWE-95", "CWE-98"]
    xss_cwes = ["CWE-79"]
    access_cwes = ["CWE-22"]
    crypto_cwes = ["CWE-327", "CWE-330"]

    if cwe in injection_cwes:
        return "A03:2021-Injection"
    elif cwe in xss_cwes:
        return "A03:2021-Injection"
    elif cwe in access_cwes:
        return "A01:2021-Broken Access Control"
    elif cwe in crypto_cwes:
        return "A02:2021-Cryptographic Failures"
    else:
        return "A06:2021-Vulnerable Components"


def get_owasp_category_from_cwe(cwe: str) -> str:
    """Map CWE to OWASP category."""
    return get_owasp_category(cwe)


def analyze_js_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single JavaScript file and return results in JSON format.
    """
    findings = run_eslint_analysis(file_path, app_name)

    return {
        "language": "javascript",
        "file": file_path,
        "analyzer": "eslint-security/regex-fallback",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for JavaScript static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python js_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_js_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
