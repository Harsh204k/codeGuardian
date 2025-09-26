#!/usr/bin/env python3
"""
C/C++ static analysis using cppcheck for security vulnerability detection.
Outputs findings in the same format as the main scanner.
"""

import json
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
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


# Mapping from cppcheck error IDs to CWE numbers
CPPCHECK_CWE_MAPPING = {
    "bufferAccessOutOfBounds": "CWE-125",
    "arrayIndexOutOfBounds": "CWE-125",
    "nullPointer": "CWE-476",
    "uninitvar": "CWE-457",
    "memleak": "CWE-401",
    "doubleFree": "CWE-415",
    "useAfterFree": "CWE-416",
    "deallocDealloc": "CWE-415",
    "mismatchAllocDealloc": "CWE-762",
    "memleakOnRealloc": "CWE-401",
    "resourceLeak": "CWE-404",
    "invalidPointerCast": "CWE-704",
    "dangerousUsageStrtok": "CWE-477",
    "sprintfOverlappingData": "CWE-628",
    "wrongPrintfScanfArgNum": "CWE-685",
    "invalidPrintfArgType_sint": "CWE-686",
    "invalidPrintfArgType_uint": "CWE-686",
    "invalidScanfArgType_int": "CWE-686",
    "wrongPrintfScanfParameterPositionError": "CWE-685",
    "va_start_wrongParameter": "CWE-685",
    "va_end_missing": "CWE-685",
    "va_list_usedBeforeStarted": "CWE-685",
    "va_start_subsequently": "CWE-685",
    "bufferNotZeroTerminated": "CWE-170",
    "possibleBufferAccessOutOfBounds": "CWE-125",
    "strncatUsage": "CWE-120",
    "terminateStrncpy": "CWE-170",
    "ctuOneDefinitionRuleViolation": "CWE-758",
    "unsafeClassCanLeak": "CWE-401",
    "functionStatic": "CWE-563",
    "functionConst": "CWE-563",
    "ConfigurationNotChecked": "CWE-252",
    "cppcheckError": "CWE-703",
    "internalAstError": "CWE-703",
    "syntaxError": "CWE-703",
    "preprocessorErrorDirective": "CWE-703",
    "toomanyconfigs": "CWE-703",
    "unknownMacro": "CWE-703",
    "missingInclude": "CWE-703",
    "missingIncludeSystem": "CWE-703",
    "unmatchedSuppression": "CWE-703",
    "checkersReport": "CWE-703",
    "normalCheckLevelMaxBranches": "CWE-703",
    "autoNoType": "CWE-665",
    "copyCtorPointerCopying": "CWE-665",
    "noCopyConstructor": "CWE-665",
    "noOperatorEq": "CWE-665",
    "operatorEqVarError": "CWE-665",
    "unusedFunction": "CWE-561",
    "unusedStructMember": "CWE-563",
    "unusedVariable": "CWE-563",
    "unreadVariable": "CWE-563",
    "unusedPrivateFunction": "CWE-561",
    "unusedLabel": "CWE-563",
    "unknownEvaluationOrder": "CWE-768",
    "argumentSize": "CWE-686",
    "arrayIndexThenCheck": "CWE-129",
    "assignBoolToPointer": "CWE-704",
    "assignmentInAssert": "CWE-571",
    "badBitmaskCheck": "CWE-571",
    "bitwiseOnBoolean": "CWE-571",
    "comparisonOfFuncReturningBoolError": "CWE-571",
    "comparisonOfTwoFuncsReturningBoolError": "CWE-571",
    "duplicateBranch": "CWE-561",
    "duplicateCondition": "CWE-571",
    "duplicateExpressionTernary": "CWE-571",
    "identicalConditionAfterEarlyExit": "CWE-571",
    "identicalInnerCondition": "CWE-571",
    "incorrectLogicOperator": "CWE-480",
    "redundantCondition": "CWE-571",
    "suspiciousCase": "CWE-484",
    "suspiciousSemicolon": "CWE-480",
}

# Severity mapping
SEVERITY_MAPPING = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "style": "LOW",
    "performance": "LOW",
    "portability": "LOW",
    "information": "LOW",
}

# Confidence mapping based on severity
CONFIDENCE_MAPPING = {
    "error": 0.9,
    "warning": 0.7,
    "style": 0.4,
    "performance": 0.4,
    "portability": 0.4,
    "information": 0.3,
}


def run_cppcheck_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run cppcheck analysis on a C/C++ file and return findings in consistent format.
    """
    findings = []

    try:
        # Run cppcheck with XML output
        cmd = [
            "cppcheck",
            "--xml",
            "--xml-version=2",
            "--enable=warning,style,performance,portability,information,missingInclude",
            "--suppress=missingIncludeSystem",
            "--suppress=unmatchedSuppression",
            "--force",  # Force checking of all configurations
            "--error-exitcode=0",  # Don't exit with error code on findings
            file_path,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0 and not result.stderr:
            print(
                f"Warning: cppcheck returned code {result.returncode}", file=sys.stderr
            )
            return findings

        if not result.stderr.strip():
            return findings

        # Parse XML output from stderr
        try:
            root = ET.fromstring(result.stderr)
        except ET.ParseError:
            # If XML parsing fails, try to extract individual error elements
            xml_content = f"<results>{result.stderr}</results>"
            try:
                root = ET.fromstring(xml_content)
            except ET.ParseError:
                print(f"Failed to parse cppcheck XML output", file=sys.stderr)
                return findings

        # Process cppcheck results
        for error_elem in root.findall(".//error"):
            error_id = error_elem.get("id", "UNKNOWN")
            severity = error_elem.get("severity", "warning")
            msg = error_elem.get("msg", "Security issue detected")

            # Get location info
            location = error_elem.find("location")
            if location is not None:
                file_name = location.get("file", file_path)
                line_num = int(location.get("line", 0))
            else:
                file_name = file_path
                line_num = 0

            # Extract snippet if possible
            snippet = ""
            try:
                if Path(file_name).exists() and line_num > 0:
                    with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        if 0 <= line_num - 1 < len(lines):
                            snippet = lines[line_num - 1].strip()[:240]
            except Exception:
                pass

            finding = Finding(
                id=f"CPP-{error_id}-{str(uuid.uuid4())[:8]}",
                app=app_name,
                language="cpp",
                rule_id=f"CPP-{error_id}",
                name=error_id.replace("_", " ").title(),
                file=file_name,
                line=line_num,
                snippet=snippet,
                cwe=CPPCHECK_CWE_MAPPING.get(error_id, "CWE-693"),
                owasp=get_owasp_category(error_id),
                severity=SEVERITY_MAPPING.get(severity, "MEDIUM"),
                confidence=CONFIDENCE_MAPPING.get(severity, 0.6),
                why=msg,
                quickfix={"type": "suggest", "message": f"Review and fix: {msg}"},
            )
            findings.append(finding)

    except subprocess.TimeoutExpired:
        print(f"Timeout running cppcheck on {file_path}", file=sys.stderr)
    except FileNotFoundError:
        print(
            "cppcheck not found. Install from: http://cppcheck.sourceforge.net/",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"Error running cppcheck: {e}", file=sys.stderr)

    return findings


def get_owasp_category(error_id: str) -> str:
    """Map error ID to OWASP category."""
    if error_id in [
        "bufferAccessOutOfBounds",
        "arrayIndexOutOfBounds",
        "possibleBufferAccessOutOfBounds",
    ]:
        return "A01:2021-Broken Access Control"
    elif error_id in ["nullPointer", "uninitvar", "useAfterFree"]:
        return "A04:2021-Insecure Design"
    elif error_id in ["memleak", "resourceLeak"]:
        return "A04:2021-Insecure Design"
    else:
        return "A06:2021-Vulnerable Components"


def analyze_cpp_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single C/C++ file and return results in JSON format.
    """
    findings = run_cppcheck_analysis(file_path, app_name)

    return {
        "language": "cpp",
        "file": file_path,
        "analyzer": "cppcheck",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for C/C++ static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python cpp_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_cpp_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
