#!/usr/bin/env python3
"""
Multi-language analyzer manager that coordinates all static analysis tools.
This serves as the central hub for routing analysis requests to appropriate language-specific analyzers.
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import importlib.util


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


class MultiLanguageAnalyzer:
    """
    Coordinates multiple language-specific static analysis tools.
    """

    def __init__(self):
        self.analyzers_dir = Path(__file__).parent
        self.supported_languages = {
            "python": "python_analyzer.py",
            "cpp": "cpp_analyzer.py",
            "c": "cpp_analyzer.py",  # Use C++ analyzer for C files
            "php": "php_analyzer.py",
            "javascript": "js_analyzer.py",
            "js": "js_analyzer.py",
            "typescript": "js_analyzer.py",  # Use JS analyzer for TypeScript
            "ts": "js_analyzer.py",
            "go": "go_analyzer.py",
            "java": "java_analyzer.py",
        }

    def get_language_from_file(self, file_path: str) -> Optional[str]:
        """
        Determine programming language from file extension.
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        extension_map = {
            ".py": "python",
            ".cpp": "cpp",
            ".cxx": "cpp",
            ".cc": "cpp",
            ".c++": "cpp",
            ".c": "c",
            ".h": "cpp",  # Treat headers as C++
            ".hpp": "cpp",
            ".php": "php",
            ".php3": "php",
            ".php4": "php",
            ".php5": "php",
            ".phtml": "php",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".class": "java",  # Compiled Java classes
        }

        return extension_map.get(ext)

    def load_analyzer(self, language: str):
        """
        Dynamically load the appropriate analyzer module.
        """
        if language not in self.supported_languages:
            return None

        analyzer_file = self.supported_languages[language]
        analyzer_path = self.analyzers_dir / analyzer_file

        if not analyzer_path.exists():
            print(f"Warning: Analyzer file {analyzer_path} not found", file=sys.stderr)
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                f"{language}_analyzer", analyzer_path
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception as e:
            print(f"Error loading analyzer for {language}: {e}", file=sys.stderr)
            return None

    def analyze_file(self, file_path: str, app_name: str = "App") -> Dict[str, Any]:
        """
        Analyze a single file using the appropriate language analyzer.
        """
        language = self.get_language_from_file(file_path)

        if not language:
            return {
                "language": "unknown",
                "file": file_path,
                "analyzer": "none",
                "findings_count": 0,
                "findings": [],
                "error": f"Unsupported file type: {Path(file_path).suffix}",
            }

        analyzer = self.load_analyzer(language)

        if not analyzer:
            return {
                "language": language,
                "file": file_path,
                "analyzer": "none",
                "findings_count": 0,
                "findings": [],
                "error": f"No analyzer available for {language}",
            }

        try:
            # Call the analyzer's main analysis function
            if hasattr(analyzer, "analyze_python_file") and language == "python":
                return analyzer.analyze_python_file(file_path, app_name)
            elif hasattr(analyzer, "analyze_cpp_file") and language in ["cpp", "c"]:
                return analyzer.analyze_cpp_file(file_path, app_name)
            elif hasattr(analyzer, "analyze_php_file") and language == "php":
                return analyzer.analyze_php_file(file_path, app_name)
            elif hasattr(analyzer, "analyze_js_file") and language in [
                "javascript",
                "js",
                "typescript",
                "ts",
            ]:
                return analyzer.analyze_js_file(file_path, app_name)
            elif hasattr(analyzer, "analyze_go_file") and language == "go":
                return analyzer.analyze_go_file(file_path, app_name)
            elif hasattr(analyzer, "analyze_java_file") and language == "java":
                return analyzer.analyze_java_file(file_path, app_name)
            else:
                return {
                    "language": language,
                    "file": file_path,
                    "analyzer": "none",
                    "findings_count": 0,
                    "findings": [],
                    "error": f"Analyzer function not found for {language}",
                }

        except Exception as e:
            return {
                "language": language,
                "file": file_path,
                "analyzer": "error",
                "findings_count": 0,
                "findings": [],
                "error": f"Analysis failed: {str(e)}",
            }

    def analyze_directory(
        self, directory_path: str, app_name: str = "App"
    ) -> Dict[str, Any]:
        """
        Analyze all supported files in a directory recursively.
        """
        results = {
            "app": app_name,
            "directory": directory_path,
            "total_files": 0,
            "analyzed_files": 0,
            "total_findings": 0,
            "results_by_language": {},
            "file_results": [],
        }

        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            results["error"] = (
                f"Directory {directory_path} does not exist or is not a directory"
            )
            return results

        # Find all supported files, but exclude large or irrelevant directories such as
        # virtualenvs, git metadata, datasets, build outputs, and node_modules.
        supported_extensions = {
            ".py",
            ".cpp",
            ".cxx",
            ".cc",
            ".c++",
            ".c",
            ".h",
            ".hpp",
            ".php",
            ".php3",
            ".php4",
            ".php5",
            ".phtml",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".go",
        }

        ignore_dirs = {
            ".venv",
            "venv",
            ".git",
            "node_modules",
            "reports",
            # "datasets",
            "build",
            "dist",
            "__pycache__",
            ".pytest_cache",
        }

        files_to_analyze = []
        # Walk the tree but skip ignored directories
        for path in directory.rglob("**/*"):
            try:
                if not path.exists():
                    continue
                # skip directories
                if path.is_dir():
                    # if any part of the path is in ignore list, skip this directory (and its children)
                    if any(part in ignore_dirs for part in path.parts):
                        # skip descending into this directory by continuing
                        continue
                    else:
                        continue

                # skip files under ignored directories
                if any(part in ignore_dirs for part in path.parts):
                    continue

                if path.suffix.lower() in supported_extensions:
                    files_to_analyze.append(path)
            except Exception:
                # be defensive: skip any path we cannot stat
                continue

        results["total_files"] = len(files_to_analyze)

        for file_path in files_to_analyze:
            file_result = self.analyze_file(str(file_path), app_name)
            results["file_results"].append(file_result)

            if file_result["findings_count"] > 0:
                results["analyzed_files"] += 1
                results["total_findings"] += file_result["findings_count"]

                language = file_result["language"]
                if language not in results["results_by_language"]:
                    results["results_by_language"][language] = {
                        "files": 0,
                        "findings": 0,
                    }
                results["results_by_language"][language]["files"] += 1
                results["results_by_language"][language]["findings"] += file_result[
                    "findings_count"
                ]

        return results

    def convert_to_findings_format(
        self, analysis_result: Dict[str, Any]
    ) -> List[Finding]:
        """
        Convert analysis result to the Finding dataclass format used by the main scanner.
        """
        findings = []

        if "file_results" in analysis_result:
            # Multiple files result
            for file_result in analysis_result["file_results"]:
                findings.extend(self._convert_single_file_findings(file_result))
        else:
            # Single file result
            findings.extend(self._convert_single_file_findings(analysis_result))

        return findings

    def _convert_single_file_findings(
        self, file_result: Dict[str, Any]
    ) -> List[Finding]:
        """Convert findings from a single file result."""
        findings = []

        for finding_dict in file_result.get("findings", []):
            try:
                finding = Finding(**finding_dict)
                findings.append(finding)
            except Exception as e:
                print(f"Error converting finding: {e}", file=sys.stderr)
                continue

        return findings


def main():
    """CLI interface for multi-language static analysis."""
    if len(sys.argv) < 2:
        print("Usage: python multi_analyzer.py <file_or_directory> [app_name]")
        sys.exit(1)

    target_path = sys.argv[1]
    app_name = sys.argv[2] if len(sys.argv) > 2 else "App"

    if not Path(target_path).exists():
        print(f"Error: {target_path} does not exist")
        sys.exit(1)

    analyzer = MultiLanguageAnalyzer()

    if Path(target_path).is_file():
        result = analyzer.analyze_file(target_path, app_name)
    else:
        result = analyzer.analyze_directory(target_path, app_name)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
