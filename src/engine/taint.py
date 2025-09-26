"""Minimal source→sink tracing for CodeGuardian."""

import re
from typing import List, Dict, Set
from .scanner import Finding


def trace(findings: List[Finding]) -> List[Finding]:
    """
    Perform basic taint analysis on findings to trace data flow from sources to sinks.
    This is a simplified implementation that looks for variable assignments and usage.
    """
    if not findings:
        return findings

    # Group findings by file for analysis
    file_findings: Dict[str, List[Finding]] = {}
    for finding in findings:
        if finding.file not in file_findings:
            file_findings[finding.file] = []
        file_findings[finding.file].append(finding)

    enhanced_findings = []

    for file_path, file_findings_list in file_findings.items():
        try:
            # Read the file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.splitlines()

            # Analyze each finding in context
            for finding in file_findings_list:
                enhanced_finding = _analyze_finding_context(finding, content, lines)
                enhanced_findings.append(enhanced_finding)

        except Exception as e:
            # If we can't analyze the file, keep the original finding
            enhanced_findings.append(finding)

    return enhanced_findings


def _analyze_finding_context(finding: Finding, content: str, lines: List[str]) -> Finding:
    """
    Analyze the context around a finding to enhance it with taint information.
    """
    # Get the line where the finding occurred
    if finding.line <= 0 or finding.line > len(lines):
        return finding

    line_content = lines[finding.line - 1]

    # Look for variable assignments and usage patterns
    # This is a very basic implementation - real taint analysis would be much more sophisticated

    # Check if this line contains a variable assignment that might be tainted
    var_match = re.search(r'(\w+)\s*=\s*.*', line_content)
    if var_match:
        var_name = var_match.group(1)
        # Look for usage of this variable in subsequent lines
        tainted_lines = _find_variable_usage(var_name, finding.line, lines)

        if tainted_lines:
            # Enhance the finding with taint information
            enhanced_why = finding.why
            if enhanced_why:
                enhanced_why += " "
            enhanced_why += f"Tainted variable '{var_name}' flows to lines: {', '.join(map(str, tainted_lines))}"

            # Create enhanced finding
            enhanced_finding = Finding(
                id=finding.id,
                app=finding.app,
                language=finding.language,
                rule_id=finding.rule_id,
                name=finding.name,
                file=finding.file,
                line=finding.line,
                snippet=finding.snippet,
                cwe=finding.cwe,
                owasp=finding.owasp,
                severity=finding.severity,
                confidence=finding.confidence,
                why=enhanced_why,
                quickfix=finding.quickfix
            )
            return enhanced_finding

    return finding


def _find_variable_usage(var_name: str, start_line: int, lines: List[str], max_lines: int = 20) -> List[int]:
    """
    Find lines where a variable is used after its assignment.
    This is a very basic implementation.
    """
    usage_lines = []
    pattern = re.compile(r'\b' + re.escape(var_name) + r'\b')

    for i in range(start_line, min(len(lines), start_line + max_lines)):
        if pattern.search(lines[i]):
            usage_lines.append(i + 1)  # Convert to 1-based line numbers

    return usage_lines[1:]  # Skip the assignment line itself
