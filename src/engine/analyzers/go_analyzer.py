#!/usr/bin/env python3
"""
Go static analysis using gosec for security vulnerability detection.
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


# Mapping from gosec rule IDs to CWE numbers
GOSEC_CWE_MAPPING = {
    "G101": "CWE-798",  # Hardcoded credentials
    "G102": "CWE-200",  # Bind to all interfaces
    "G103": "CWE-489",  # Audit the use of unsafe block
    "G104": "CWE-252",  # Audit errors not checked
    "G105": "CWE-88",  # Audit the use of math/big.Int.Exp
    "G106": "CWE-295",  # Audit the use of ssh.InsecureIgnoreHostKey
    "G107": "CWE-200",  # Url provided to HTTP request as taint input
    "G108": "CWE-94",  # Profiling endpoint automatically exposed
    "G109": "CWE-190",  # Integer overflow/underflow
    "G110": "CWE-409",  # Potential DoS vulnerability via decompression bomb
    "G201": "CWE-89",  # SQL query construction using format string
    "G202": "CWE-89",  # SQL query construction using string concatenation
    "G203": "CWE-79",  # Use of unescaped data in HTML templates
    "G204": "CWE-78",  # Audit use of command execution
    "G301": "CWE-22",  # Poor file permissions used when creating a directory
    "G302": "CWE-276",  # Poor file permissions used when creation file or using chmod
    "G303": "CWE-377",  # Creating tempfile using a predictable path
    "G304": "CWE-22",  # File path provided as taint input
    "G305": "CWE-22",  # File traversal when extracting zip archive
    "G306": "CWE-276",  # Poor file permissions used when writing to a file
    "G307": "CWE-703",  # Poor file permissions used when creating a file with os.Create
    "G401": "CWE-327",  # Detect the usage of DES, RC4, MD5 or SHA1
    "G402": "CWE-295",  # Look for bad TLS connection settings
    "G403": "CWE-327",  # Ensure minimum RSA key length of 2048 bits
    "G404": "CWE-330",  # Insecure random number source (rand)
    "G501": "CWE-327",  # Import blacklist: crypto/md5
    "G502": "CWE-327",  # Import blacklist: crypto/des
    "G503": "CWE-327",  # Import blacklist: crypto/rc4
    "G504": "CWE-327",  # Import blacklist: net/http/cgi
    "G505": "CWE-327",  # Import blacklist: crypto/sha1
    "G601": "CWE-200",  # Implicit memory aliasing of items from a range statement
}

# Severity mapping based on gosec severity
SEVERITY_MAPPING = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

# Confidence mapping based on gosec confidence
CONFIDENCE_MAPPING = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}


def run_simple_go_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run a simple regex-based Go security analysis when gosec is not available.
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

        # Define security patterns for Go
        security_patterns = [
            {
                "pattern": r"exec\.Command\s*\(",
                "name": "Command execution",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "Command execution can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"exec\.CommandContext\s*\(",
                "name": "Command execution with context",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "Command execution can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"sql\.Query\s*\([^)]*\+",
                "name": "SQL injection via string concatenation",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "message": "SQL query with string concatenation can lead to injection",
            },
            {
                "pattern": r"fmt\.Sprintf\s*\([^)]*SELECT.*%s",
                "name": "SQL injection via sprintf",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "message": "SQL query formatting with sprintf can lead to injection",
            },
            {
                "pattern": r"template\.HTML\s*\(",
                "name": "Unsafe HTML template",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "template.HTML bypasses auto-escaping and can lead to XSS",
            },
            {
                "pattern": r"template\.HTMLAttr\s*\(",
                "name": "Unsafe HTML attribute",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "template.HTMLAttr bypasses auto-escaping",
            },
            {
                "pattern": r"template\.JS\s*\(",
                "name": "Unsafe JavaScript template",
                "cwe": "CWE-79",
                "severity": "MEDIUM",
                "message": "template.JS bypasses auto-escaping",
            },
            {
                "pattern": r"math/rand",
                "name": "Weak random number generator",
                "cwe": "CWE-330",
                "severity": "MEDIUM",
                "message": "math/rand is not cryptographically secure",
            },
            {
                "pattern": r"crypto/md5",
                "name": "Weak hash algorithm MD5",
                "cwe": "CWE-327",
                "severity": "MEDIUM",
                "message": "MD5 is cryptographically weak",
            },
            {
                "pattern": r"crypto/sha1",
                "name": "Weak hash algorithm SHA1",
                "cwe": "CWE-327",
                "severity": "MEDIUM",
                "message": "SHA1 is cryptographically weak",
            },
            {
                "pattern": r"crypto/des",
                "name": "Weak encryption DES",
                "cwe": "CWE-327",
                "severity": "HIGH",
                "message": "DES encryption is cryptographically weak",
            },
            {
                "pattern": r"crypto/rc4",
                "name": "Weak encryption RC4",
                "cwe": "CWE-327",
                "severity": "HIGH",
                "message": "RC4 encryption is cryptographically weak",
            },
            {
                "pattern": r"InsecureSkipVerify:\s*true",
                "name": "TLS certificate verification disabled",
                "cwe": "CWE-295",
                "severity": "HIGH",
                "message": "Disabling TLS certificate verification is insecure",
            },
            {
                "pattern": r"os\.Create\s*\(",
                "name": "File creation with default permissions",
                "cwe": "CWE-276",
                "severity": "MEDIUM",
                "message": "os.Create uses default file permissions which may be too permissive",
            },
            {
                "pattern": r'ioutil\.TempFile\s*\([^)]*,\s*[\'"][^\'")]*[\'"]',
                "name": "Predictable temporary file",
                "cwe": "CWE-377",
                "severity": "MEDIUM",
                "message": "Temporary files with predictable names can be security risk",
            },
            {
                "pattern": r'net/http\.ListenAndServe\s*\([\'"]:[0-9]+[\'"]',
                "name": "Bind to all interfaces",
                "cwe": "CWE-200",
                "severity": "MEDIUM",
                "message": "Binding to all interfaces can expose service unnecessarily",
            },
            {
                "pattern": r"unsafe\.",
                "name": "Unsafe package usage",
                "cwe": "CWE-119",
                "severity": "HIGH",
                "message": "Use of unsafe package can lead to memory safety issues",
            },
            {
                "pattern": r'password.*=.*[\'"][^\'")]*[\'"]',
                "name": "Hardcoded password",
                "cwe": "CWE-798",
                "severity": "HIGH",
                "message": "Hardcoded credentials should not be used",
            },
            {
                "pattern": r'token.*=.*[\'"][^\'")]*[\'"]',
                "name": "Hardcoded token",
                "cwe": "CWE-798",
                "severity": "HIGH",
                "message": "Hardcoded tokens should not be used",
            },
        ]

        for i, line in enumerate(lines, 1):
            for pattern_def in security_patterns:
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    finding = Finding(
                        id=f"GO-REGEX-{str(uuid.uuid4())[:8]}",
                        app=app_name,
                        language="go",
                        rule_id=f"GO-{pattern_def['name'].replace(' ', '_').upper()}",
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
        print(f"Error in simple Go analysis: {e}", file=sys.stderr)

    return findings


def run_gosec_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run gosec analysis on a Go file and return findings in consistent format.
    Falls back to simple regex analysis if gosec is not available.
    """
    findings = []

    try:
        # Run gosec with JSON output
        cmd = ["gosec", "-fmt", "json", "-quiet", file_path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode not in [0, 1]:  # gosec returns 1 when issues found
            print(f"Warning: gosec returned code {result.returncode}", file=sys.stderr)
            return run_simple_go_analysis(file_path, app_name)

        if not result.stdout.strip():
            return findings

        try:
            gosec_output = json.loads(result.stdout)

            # Process gosec results
            for issue in gosec_output.get("Issues", []):
                rule_id = issue.get("rule_id", "UNKNOWN")
                severity = issue.get("severity", "MEDIUM")
                confidence = issue.get("confidence", "MEDIUM")

                finding = Finding(
                    id=f"GO-{rule_id}-{str(uuid.uuid4())[:8]}",
                    app=app_name,
                    language="go",
                    rule_id=f"GO-{rule_id}",
                    name=issue.get("details", rule_id),
                    file=issue.get("file", file_path),
                    line=int(issue.get("line", 0)),
                    snippet=issue.get("code", "").strip()[:240],
                    cwe=GOSEC_CWE_MAPPING.get(rule_id, "CWE-693"),
                    owasp=get_owasp_category_from_cwe(
                        GOSEC_CWE_MAPPING.get(rule_id, "CWE-693")
                    ),
                    severity=SEVERITY_MAPPING.get(severity, "MEDIUM"),
                    confidence=CONFIDENCE_MAPPING.get(confidence, 0.6),
                    why=issue.get("details", "Security vulnerability detected"),
                    quickfix={
                        "type": "suggest",
                        "message": f"Review and fix: {issue.get('details', '')}",
                    },
                )
                findings.append(finding)

        except json.JSONDecodeError:
            print(
                "Failed to parse gosec JSON output, falling back to regex analysis",
                file=sys.stderr,
            )
            return run_simple_go_analysis(file_path, app_name)

    except subprocess.TimeoutExpired:
        print(f"Timeout running gosec on {file_path}", file=sys.stderr)
        return run_simple_go_analysis(file_path, app_name)
    except FileNotFoundError:
        print("gosec not found, using fallback regex analysis", file=sys.stderr)
        return run_simple_go_analysis(file_path, app_name)
    except Exception as e:
        print(
            f"Error running gosec: {e}, falling back to regex analysis", file=sys.stderr
        )
        return run_simple_go_analysis(file_path, app_name)

    return findings


def get_owasp_category(cwe: str) -> str:
    """Map CWE to OWASP category."""
    injection_cwes = ["CWE-89", "CWE-78", "CWE-95", "CWE-94"]
    xss_cwes = ["CWE-79"]
    access_cwes = ["CWE-22", "CWE-276"]
    crypto_cwes = ["CWE-327", "CWE-330", "CWE-295"]
    auth_cwes = ["CWE-798"]

    if cwe in injection_cwes:
        return "A03:2021-Injection"
    elif cwe in xss_cwes:
        return "A03:2021-Injection"
    elif cwe in access_cwes:
        return "A01:2021-Broken Access Control"
    elif cwe in crypto_cwes:
        return "A02:2021-Cryptographic Failures"
    elif cwe in auth_cwes:
        return "A07:2021-Identification and Authentication Failures"
    else:
        return "A06:2021-Vulnerable Components"


def get_owasp_category_from_cwe(cwe: str) -> str:
    """Map CWE to OWASP category."""
    return get_owasp_category(cwe)


def analyze_go_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single Go file and return results in JSON format.
    """
    findings = run_gosec_analysis(file_path, app_name)

    return {
        "language": "go",
        "file": file_path,
        "analyzer": "gosec/regex-fallback",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for Go static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python go_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_go_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
