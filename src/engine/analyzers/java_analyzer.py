#!/usr/bin/env python3
"""
Java static analysis using SpotBugs for security vulnerability detection.
Outputs findings in the same format as the main scanner.
"""

import json
import subprocess
import sys
import tempfile
import uuid
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


# Mapping from SpotBugs bug types to CWE numbers
SPOTBUGS_CWE_MAPPING = {
    "SQL_INJECTION": "CWE-89",
    "XSS_REQUEST_PARAMETER": "CWE-79",
    "XSS_SERVLET": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL_IN": "CWE-22",
    "PATH_TRAVERSAL_OUT": "CWE-22",
    "WEAK_TRUST_MANAGER": "CWE-295",
    "WEAK_HOSTNAME_VERIFIER": "CWE-295",
    "WEAK_MESSAGE_DIGEST_MD5": "CWE-327",
    "WEAK_MESSAGE_DIGEST_SHA1": "CWE-327",
    "HARD_CODE_PASSWORD": "CWE-798",
    "HARD_CODE_KEY": "CWE-798",
    "INSECURE_COOKIE": "CWE-614",
    "HTTPONLY_COOKIE": "CWE-1004",
    "MALICIOUS_CODE": "CWE-502",
    "XXE": "CWE-611",
    "RANDOM": "CWE-338",
    "DES_USAGE": "CWE-327",
    "RSA_NO_PADDING": "CWE-780",
    "NULL_CIPHER": "CWE-327",
}


def run_spotbugs_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run SpotBugs analysis on a Java file.
    """
    findings = []

    try:
        # Check if spotbugs is available
        result = subprocess.run(
            ["spotbugs", "--version"], capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            print("Warning: SpotBugs not found. Install with: apt-get install spotbugs")
            return findings

    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("Warning: SpotBugs not available. Install with: apt-get install spotbugs")
        return findings

    try:
        # Create temporary directory for analysis
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Compile Java file first (if not already compiled)
            java_file = Path(file_path)
            if java_file.suffix.lower() == ".java":
                # Try to compile the Java file
                class_file = temp_path / (java_file.stem + ".class")
                compile_result = subprocess.run(
                    ["javac", "-d", str(temp_path), str(java_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if compile_result.returncode != 0:
                    # If compilation fails, try to analyze the source directly
                    # This is a fallback - SpotBugs works better with compiled classes
                    print(
                        f"Warning: Could not compile {file_path}: {compile_result.stderr}"
                    )
                    return findings

                # Run SpotBugs on the compiled class
                spotbugs_result = subprocess.run(
                    [
                        "spotbugs",
                        "-textui",
                        "-low",
                        "-xml:withMessages",
                        "-output",
                        str(temp_path / "spotbugs_result.xml"),
                        str(class_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if spotbugs_result.returncode == 0:
                    # Parse the XML output (simplified parsing)
                    xml_file = temp_path / "spotbugs_result.xml"
                    if xml_file.exists():
                        findings = parse_spotbugs_xml(
                            str(xml_file), file_path, app_name
                        )

            else:
                # Assume it's already a compiled .class file
                spotbugs_result = subprocess.run(
                    [
                        "spotbugs",
                        "-textui",
                        "-low",
                        "-xml:withMessages",
                        "-output",
                        str(temp_path / "spotbugs_result.xml"),
                        str(java_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if spotbugs_result.returncode == 0:
                    xml_file = temp_path / "spotbugs_result.xml"
                    if xml_file.exists():
                        findings = parse_spotbugs_xml(
                            str(xml_file), file_path, app_name
                        )

    except subprocess.TimeoutExpired:
        print(f"Warning: SpotBugs analysis timed out for {file_path}")
    except Exception as e:
        print(f"Warning: SpotBugs analysis failed for {file_path}: {e}")

    return findings


def parse_spotbugs_xml(xml_file: str, source_file: str, app_name: str) -> List[Finding]:
    """
    Parse SpotBugs XML output and convert to our Finding format.
    """
    findings = []

    try:
        # Simple XML parsing (in production, use proper XML parser)
        with open(xml_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract BugInstance entries
        import re

        bug_pattern = r'<BugInstance[^>]*type="([^"]*)"[^>]*>.*?<SourceLine[^>]*start="(\d*)"[^>]*>.*?<Message>([^<]*)</Message>.*?</BugInstance>'
        matches = re.findall(bug_pattern, content, re.DOTALL)

        for bug_type, line_num, message in matches:
            try:
                line = int(line_num)
                cwe = SPOTBUGS_CWE_MAPPING.get(bug_type, "CWE-UNKNOWN")

                # Map severity based on bug type
                severity = "MEDIUM"
                if "HIGH" in bug_type or "CRITICAL" in bug_type:
                    severity = "HIGH"
                elif "LOW" in bug_type:
                    severity = "LOW"

                # Get code snippet
                try:
                    with open(source_file, "r", encoding="utf-8") as sf:
                        lines = sf.readlines()
                        snippet = (
                            lines[line - 1].strip()[:240]
                            if 0 <= line - 1 < len(lines)
                            else ""
                        )
                except:
                    snippet = ""

                finding = Finding(
                    id=f"SPOTBUGS-{str(uuid.uuid4())[:8]}",
                    app=app_name,
                    language="java",
                    rule_id=bug_type,
                    name=f"SpotBugs: {bug_type}",
                    file=source_file,
                    line=line,
                    snippet=snippet,
                    cwe=cwe,
                    owasp="-",
                    severity=severity,
                    confidence=0.8,  # SpotBugs is generally reliable
                    why=f"SpotBugs detected: {message}",
                    quickfix=None,
                )
                findings.append(finding)

            except (ValueError, IndexError) as e:
                continue

    except Exception as e:
        print(f"Warning: Failed to parse SpotBugs XML output: {e}")

    return findings


def analyze_java_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single Java file and return results in JSON format.
    """
    findings = run_spotbugs_analysis(file_path, app_name)

    return {
        "language": "java",
        "file": file_path,
        "analyzer": "spotbugs",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for Java static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python java_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_java_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
