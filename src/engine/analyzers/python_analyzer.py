#!/usr/bin/env python3
"""
Python static analysis using bandit for security vulnerability detection.
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


# Mapping from bandit test IDs to CWE numbers
BANDIT_CWE_MAPPING = {
    "B101": "CWE-798",  # assert_used
    "B102": "CWE-78",  # exec_used
    "B103": "CWE-703",  # set_bad_file_permissions
    "B104": "CWE-200",  # hardcoded_bind_all_interfaces
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B201": "CWE-95",  # flask_debug_true
    "B301": "CWE-502",  # pickle
    "B302": "CWE-295",  # marshal
    "B303": "CWE-327",  # md5
    "B304": "CWE-327",  # des
    "B305": "CWE-327",  # cipher
    "B306": "CWE-327",  # mktemp_q
    "B307": "CWE-78",  # eval
    "B308": "CWE-327",  # mark_safe
    "B309": "CWE-295",  # httpsconnection
    "B310": "CWE-330",  # urllib_urlopen
    "B311": "CWE-330",  # random
    "B312": "CWE-327",  # telnetlib
    "B313": "CWE-79",  # xml_bad_cElementTree
    "B314": "CWE-79",  # xml_bad_ElementTree
    "B315": "CWE-79",  # xml_bad_expat
    "B316": "CWE-79",  # xml_bad_minidom
    "B317": "CWE-79",  # xml_bad_pulldom
    "B318": "CWE-79",  # xml_bad_xmlrpc
    "B319": "CWE-79",  # xml_bad_etree
    "B320": "CWE-79",  # xml_bad_lxml
    "B321": "CWE-295",  # ftplib
    "B322": "CWE-776",  # input
    "B323": "CWE-703",  # unverified_context
    "B324": "CWE-327",  # hashlib_new_insecure_functions
    "B325": "CWE-377",  # tempnam
    "B401": "CWE-78",  # import_telnetlib
    "B402": "CWE-295",  # import_ftplib
    "B403": "CWE-502",  # import_pickle
    "B404": "CWE-78",  # import_subprocess
    "B405": "CWE-79",  # import_xml_etree
    "B406": "CWE-79",  # import_xml_sax
    "B407": "CWE-79",  # import_xml_expat
    "B408": "CWE-79",  # import_xml_minidom
    "B409": "CWE-79",  # import_xml_pulldom
    "B410": "CWE-79",  # import_lxml
    "B411": "CWE-79",  # import_xmlrpclib
    "B412": "CWE-295",  # import_httpoxy
    "B413": "CWE-502",  # import_pycrypto
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-295",  # ssl_with_bad_version
    "B503": "CWE-295",  # ssl_with_bad_defaults
    "B504": "CWE-295",  # ssl_with_no_version
    "B505": "CWE-327",  # weak_cryptographic_key
    "B506": "CWE-798",  # yaml_load
    "B507": "CWE-79",  # ssh_no_host_key_verification
    "B601": "CWE-77",  # paramiko_calls
    "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",  # subprocess_without_shell_equals_false
    "B604": "CWE-78",  # any_other_function_with_shell_equals_true
    "B605": "CWE-78",  # start_process_with_a_shell
    "B606": "CWE-78",  # start_process_with_no_shell
    "B607": "CWE-78",  # start_process_with_partial_path
    "B608": "CWE-89",  # hardcoded_sql_expressions
    "B609": "CWE-78",  # linux_commands_wildcard_injection
    "B610": "CWE-79",  # django_extra_used
    "B611": "CWE-79",  # django_rawsql_used
    "B701": "CWE-703",  # jinja2_autoescape_false
    "B702": "CWE-295",  # use_of_mako_templates
    "B703": "CWE-79",  # django_mark_safe
}

# Severity mapping
SEVERITY_MAPPING = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}

# Confidence mapping
CONFIDENCE_MAPPING = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}


def run_bandit_analysis(file_path: str, app_name: str = "App") -> List[Finding]:
    """
    Run bandit analysis on a Python file and return findings in consistent format.
    """
    findings = []

    try:
        # Run bandit with JSON output
        cmd = ["bandit", "-f", "json", "-r", file_path]  # recursive

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode not in [0, 1]:  # bandit returns 1 when issues found
            print(f"Warning: bandit returned code {result.returncode}", file=sys.stderr)
            return findings

        if not result.stdout.strip():
            return findings

        bandit_output = json.loads(result.stdout)

        # Process bandit results
        for result_item in bandit_output.get("results", []):
            test_id = result_item.get("test_id", "UNKNOWN")

            finding = Finding(
                id=f"PY-{test_id}-{str(uuid.uuid4())[:8]}",
                app=app_name,
                language="python",
                rule_id=f"PY-{test_id}",
                name=result_item.get("test_name", "Security Issue"),
                file=result_item.get("filename", ""),
                line=result_item.get("line_number", 0),
                snippet=result_item.get("code", "").strip()[:240],
                cwe=BANDIT_CWE_MAPPING.get(test_id, "CWE-693"),
                owasp=(
                    "A03:2021-Injection"
                    if test_id in ["B608", "B609"]
                    else "A06:2021-Vulnerable Components"
                ),
                severity=SEVERITY_MAPPING.get(
                    result_item.get("issue_severity", "MEDIUM"), "MEDIUM"
                ),
                confidence=CONFIDENCE_MAPPING.get(
                    result_item.get("issue_confidence", "MEDIUM"), 0.6
                ),
                why=result_item.get("issue_text", "Security vulnerability detected"),
                quickfix={
                    "type": "suggest",
                    "message": f"Review and fix: {result_item.get('issue_text', '')}",
                },
            )
            findings.append(finding)

    except subprocess.TimeoutExpired:
        print(f"Timeout running bandit on {file_path}", file=sys.stderr)
    except FileNotFoundError:
        print("bandit not found. Install with: pip install bandit", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Failed to parse bandit output: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Error running bandit: {e}", file=sys.stderr)

    return findings


def analyze_python_file(file_path: str, app_name: str = "App") -> Dict[str, Any]:
    """
    Analyze a single Python file and return results in JSON format.
    """
    findings = run_bandit_analysis(file_path, app_name)

    return {
        "language": "python",
        "file": file_path,
        "analyzer": "bandit",
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main():
    """CLI interface for Python static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python python_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    result = analyze_python_file(target_path, app_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
