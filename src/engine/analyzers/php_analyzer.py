#!/usr/bin/env python3
"""
PHP static analysis using phpcs with security ruleset for vulnerability detection.
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


# Mapping from common PHP security issues to CWE numbers
PHP_CWE_MAPPING = {
    "Security.BadFunctions.Asserts": "CWE-489",
    "Security.BadFunctions.CallbackFunctions": "CWE-95",
    "Security.BadFunctions.CryptoFunctions": "CWE-327",
    "Security.BadFunctions.EasyRFI": "CWE-98",
    "Security.BadFunctions.EasyXSS": "CWE-79",
    "Security.BadFunctions.ErrorHandling": "CWE-209",
    "Security.BadFunctions.FilesystemFunctions": "CWE-22",
    "Security.BadFunctions.FringeFunctions": "CWE-94",
    "Security.BadFunctions.Mysqli": "CWE-89",
    "Security.BadFunctions.NoEvals": "CWE-95",
    "Security.BadFunctions.Phpinfos": "CWE-200",
    "Security.BadFunctions.PregReplace": "CWE-95",
    "Security.BadFunctions.SQLFunctions": "CWE-89",
    "Security.BadFunctions.SystemExecFunctions": "CWE-78",
    "Security.CVE.20132110": "CWE-22",
    "Security.CVE.20134113": "CWE-79",
    "Security.Drupal7.AdvisoriesContrib": "CWE-693",
    "Security.Drupal7.AdvisoriesCore": "CWE-693",
    "Security.Drupal7.DbQueryAcl": "CWE-89",
    "Security.Drupal7.DynQueries": "CWE-89",
    "Security.Drupal7.UserInputWatch": "CWE-20",
    "Security.Drupal7.XSSPTheme": "CWE-79",
    "Security.Misc.BadCorsHeader": "CWE-346",
    "Security.Misc.IncludeMismatch": "CWE-98",
    "Security.Symfony2.SensitiveVariables": "CWE-200",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "file_inclusion": "CWE-98",
    "path_traversal": "CWE-22",
    "unsafe_eval": "CWE-95",
    "information_disclosure": "CWE-200",
    "weak_crypto": "CWE-327",
    "csrf": "CWE-352",
    "session_fixation": "CWE-384",
}


# Severity mapping based on message content
def get_severity_from_message(message: str) -> str:
    """Determine severity based on message content."""
    message_lower = message.lower()

    if any(
        keyword in message_lower
        for keyword in ["injection", "eval", "execute", "system", "exec"]
    ):
        return "HIGH"
    elif any(
        keyword in message_lower
        for keyword in ["xss", "csrf", "path traversal", "file inclusion"]
    ):
        return "HIGH"
    elif any(
        keyword in message_lower
        for keyword in ["crypto", "hash", "password", "session"]
    ):
        return "MEDIUM"
    elif any(
        keyword in message_lower for keyword in ["warning", "deprecated", "notice"]
    ):
        return "LOW"
    else:
        return "MEDIUM"


def get_cwe_from_message(message: str, rule_id: str) -> str:
    """Extract CWE from message or rule ID."""
    if rule_id in PHP_CWE_MAPPING:
        return PHP_CWE_MAPPING[rule_id]

    message_lower = message.lower()

    # Check for common vulnerability patterns
    if "sql" in message_lower and "injection" in message_lower:
        return "CWE-89"
    elif "xss" in message_lower or "cross-site" in message_lower:
        return "CWE-79"
    elif "command" in message_lower and (
        "injection" in message_lower or "execution" in message_lower
    ):
        return "CWE-78"
    elif "file" in message_lower and "inclusion" in message_lower:
        return "CWE-98"
    elif "path" in message_lower and "traversal" in message_lower:
        return "CWE-22"
    elif "eval" in message_lower or "code injection" in message_lower:
        return "CWE-95"
    elif "information" in message_lower and "disclosure" in message_lower:
        return "CWE-200"
    elif "crypto" in message_lower or "hash" in message_lower:
        return "CWE-327"
    elif "csrf" in message_lower:
        return "CWE-352"
    else:
        return "CWE-693"


def run_simple_php_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run a simple regex-based PHP security analysis when phpcs is not available.
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

        # Define security patterns
        security_patterns = [
            {
                "pattern": r"\beval\s*\(",
                "name": "Dangerous eval() function",
                "cwe": "CWE-95",
                "severity": "HIGH",
                "message": "Use of eval() can lead to code injection vulnerabilities",
            },
            {
                "pattern": r"\bexec\s*\(",
                "name": "Command execution function",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "exec() can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"\bsystem\s*\(",
                "name": "System command execution",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "system() can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"\bshell_exec\s*\(",
                "name": "Shell command execution",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "shell_exec() can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"\bpassthru\s*\(",
                "name": "Command passthrough",
                "cwe": "CWE-78",
                "severity": "HIGH",
                "message": "passthru() can lead to command injection vulnerabilities",
            },
            {
                "pattern": r"mysql_query\s*\([^)]*\$",
                "name": "SQL injection via mysql_query",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "message": "Direct variable interpolation in SQL query can lead to injection",
            },
            {
                "pattern": r"SELECT\s+.*\$[^;]*;",
                "name": "Potential SQL injection",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "message": "Direct variable use in SQL query without parameterization",
            },
            {
                "pattern": r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
                "name": "XSS via direct output",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "Direct output of user input can lead to XSS",
            },
            {
                "pattern": r"print\s+\$_(GET|POST|REQUEST|COOKIE)",
                "name": "XSS via direct print",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "message": "Direct printing of user input can lead to XSS",
            },
            {
                "pattern": r"include\s+\$_(GET|POST|REQUEST)",
                "name": "File inclusion vulnerability",
                "cwe": "CWE-98",
                "severity": "HIGH",
                "message": "Including files based on user input can lead to RFI/LFI",
            },
            {
                "pattern": r"require\s+\$_(GET|POST|REQUEST)",
                "name": "File inclusion vulnerability",
                "cwe": "CWE-98",
                "severity": "HIGH",
                "message": "Requiring files based on user input can lead to RFI/LFI",
            },
            {
                "pattern": r"file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)",
                "name": "File access via user input",
                "cwe": "CWE-22",
                "severity": "MEDIUM",
                "message": "Accessing files based on user input without validation",
            },
            {
                "pattern": r"md5\s*\(",
                "name": "Weak hash function MD5",
                "cwe": "CWE-327",
                "severity": "MEDIUM",
                "message": "MD5 is cryptographically weak, use stronger hash functions",
            },
            {
                "pattern": r"sha1\s*\(",
                "name": "Weak hash function SHA1",
                "cwe": "CWE-327",
                "severity": "MEDIUM",
                "message": "SHA1 is cryptographically weak, use SHA-256 or better",
            },
            {
                "pattern": r"\bunserialize\s*\(\s*\$_(GET|POST|REQUEST)",
                "name": "Unsafe deserialization",
                "cwe": "CWE-502",
                "severity": "HIGH",
                "message": "Unserializing user input can lead to object injection",
            },
        ]

        for i, line in enumerate(lines, 1):
            for pattern_def in security_patterns:
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    finding = Finding(
                        id=f"PHP-REGEX-{str(uuid.uuid4())[:8]}",
                        app=app_name,
                        language="php",
                        rule_id=f"PHP-{pattern_def['name'].replace(' ', '_').upper()}",
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
        print(f"Error in simple PHP analysis: {e}", file=sys.stderr)

    return findings


def run_phpcs_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run phpcs analysis with security standards on a PHP file.
    Falls back to simple regex analysis if phpcs is not available.
    """
    findings = []

    try:
        # Try to run phpcs with security standard
        cmd = [
            "phpcs",
            "--standard=Security",
            "--report=json",
            "--severity=1",
            file_path,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 and not result.stdout.strip():
            return findings

        if result.stdout.strip():
            try:
                phpcs_output = json.loads(result.stdout)

                # Process phpcs results
                for file_data in phpcs_output.get("files", {}).values():
                    for message in file_data.get("messages", []):
                        rule_id = message.get("source", "UNKNOWN")
                        msg_text = message.get("message", "Security issue detected")

                        finding = Finding(
                            id=f"PHP-{rule_id.split('.')[-1]}-{str(uuid.uuid4())[:8]}",
                            app=app_name,
                            language="php",
                            rule_id=f"PHP-{rule_id}",
                            name=rule_id.split(".")[-1].replace("_", " ").title(),
                            file=file_path,
                            line=message.get("line", 0),
                            snippet=get_line_snippet(file_path, message.get("line", 0)),
                            cwe=get_cwe_from_message(msg_text, rule_id),
                            owasp=get_owasp_category_from_cwe(
                                get_cwe_from_message(msg_text, rule_id)
                            ),
                            severity=get_severity_from_message(msg_text),
                            confidence=0.8 if message.get("type") == "ERROR" else 0.6,
                            why=msg_text,
                            quickfix={
                                "type": "suggest",
                                "message": f"Review and fix: {msg_text}",
                            },
                        )
                        findings.append(finding)

            except json.JSONDecodeError:
                print(
                    "Failed to parse phpcs JSON output, falling back to regex analysis",
                    file=sys.stderr,
                )
                return run_simple_php_analysis(file_path, app_name)

    except subprocess.TimeoutExpired:
        print(f"Timeout running phpcs on {file_path}", file=sys.stderr)
        return run_simple_php_analysis(file_path, app_name)
    except FileNotFoundError:
        print("phpcs not found, using fallback regex analysis", file=sys.stderr)
        return run_simple_php_analysis(file_path, app_name)
    except Exception as e:
        print(
            f"Error running phpcs: {e}, falling back to regex analysis", file=sys.stderr
        )
        return run_simple_php_analysis(file_path, app_name)

    return findings


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
    crypto_cwes = ["CWE-327"]

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


def analyze_php_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single PHP file and return results in JSON format.
    """
    findings = run_phpcs_analysis(file_path, app_name)

    return {
        "language": "php",
        "file": file_path,
        "analyzer": "phpcs-security/regex-fallback",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for PHP static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python php_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_php_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
