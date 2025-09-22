import os, textwrap, pathlib

root = pathlib.Path(".").resolve()

dirs = [
    "engine",
    "engine/reporters",
    "rules",
    "demos/vulnerable_py",
    "demos/vulnerable_java",
    "tests",
]

files_with_content = {
    "cli.py": """\
        # Entry point for CodeGuardian CLI
        # Usage: python -m codeguardian.cli or `python cli.py`
        if __name__ == "__main__":
            print("CodeGuardian CLI (stub). TODO: add argparse + commands.")
    """,
    "requirements.txt": """\
        pyyaml
        regex
        requests
        openpyxl
        jinja2
        # (optional) sarif-om or sarif-tools if you prefer helpers
        # syft (if you’ll shell out to Anchore Syft for SBOMs)
    """,
    ".cgignore": """\
        # Default ignore patterns
        .git/
        .venv/
        __pycache__/
        node_modules/
        .*/*.min.*
        dist/
        build/
        *.zip
        *.tar.gz
    """,
    "README.md": """\
        # CodeGuardian

        A lightweight static analysis and quick-fix engine.

        ## Structure
        - `engine/` core modules (walker, rules, scanner, taint, deps, ranking, explain, fixes)
        - `engine/reporters/` exporters (Excel, SARIF, HTML)
        - `rules/` YAML rule packs per language
        - `demos/` vulnerable sample projects
        - `tests/` unit tests
    """,

    "engine/__init__.py": "",
    "engine/walker.py": """\
        \"\"\"Repo walking, language detection, and .cgignore handling (stub).\"\"\"
        def walk_repo(path):  # TODO
            return []
    """,
    "engine/rules_loader.py": """\
        \"\"\"Load YAML rules per language (stub).\"\"\"
        import yaml
        def load_rules(path):  # TODO
            return {}
    """,
    "engine/scanner.py": """\
        \"\"\"Run rules (regex + simple flow) over files (stub).\"\"\"
        def scan(files, rules):  # TODO
            return []
    """,
    "engine/taint.py": """\
        \"\"\"Minimal source→sink tracing (Week 2 stub).\"\"\"
        def trace(findings):  # TODO
            return findings
    """,
    "engine/deps.py": """\
        \"\"\"SBOM + CVE (wrapper to syft/osv) (stub).\"\"\"
        def analyze_deps(path):  # TODO
            return []
    """,
    "engine/ranker.py": """\
        \"\"\"Severity + confidence ranking (stub).\"\"\"
        def rank(findings):  # TODO
            return findings
    """,
    "engine/explain.py": """\
        \"\"\"Short 'why' text (rule + trace) (stub).\"\"\"
        def explain(finding):  # TODO
            return "Reason (stub)"
    """,
    "engine/fixes.py": """\
        \"\"\"Quick-fix engine (apply/rollback) (stub).\"\"\"
        def apply_fix(finding):  # TODO
            return False
    """,

    "engine/reporters/excel_exporter.py": """\
        \"\"\"Excel exporter with EXACT jury columns (stub).\"\"\"
        def export(findings, out_path):  # TODO
            pass
    """,
    "engine/reporters/sarif_exporter.py": """\
        \"\"\"SARIF 2.1.0 minimal exporter (stub).\"\"\"
        def export_sarif(findings, out_path):  # TODO
            pass
    """,
    "engine/reporters/html_reporter.py": """\
        \"\"\"Clean human-readable HTML report (stub).\"\"\"
        def export_html(findings, out_path):  # TODO
            pass
    """,

    "rules/python.yml": """\
        # Example Python rules (stub)
        # - id: PY-001
        #   pattern: "eval\\("
        #   message: "Avoid eval() - code injection risk"
        #   severity: HIGH
        #   cwe: CWE-94
        #   owasp: A03:2021
    """,
    "rules/java.yml": "# Java rules (stub)\n",
    "rules/cpp.yml": "# C/C++ rules (stub)\n",
    "rules/csharp.yml": "# C# rules (stub)\n",
    "rules/php.yml": "# PHP rules (stub)\n",

    "tests/test_scanner.py": """\
        def test_scanner_smoke():
            assert True
    """,
    "tests/test_exporters.py": """\
        def test_exporters_smoke():
            assert True
    """,
}

# Make directories
for d in dirs:
    (root / d).mkdir(parents=True, exist_ok=True)

# Write files
for rel, content in files_with_content.items():
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():  # don’t overwrite if already present
        p.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")

print("✅ CodeGuardian skeleton created at:", root)
