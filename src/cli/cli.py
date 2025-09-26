#!/usr/bin/env python3
"""
Enhanced CLI for Hybrid Vulnerability Detection System
Combines rule-based detection with ML-enhanced semantic analysis
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.ml.hybrid_detector import HybridVulnerabilityScanner


def setup_args():
    """Setup command line arguments"""
    parser = argparse.ArgumentParser(
        description="CodeGuardian: Hybrid Vulnerability Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detection Modes:
  rules    - Traditional rule-based detection only
  ml       - ML-based semantic analysis only  
  hybrid   - Combined rule + ML approach (recommended)

Examples:
  python enhanced_cli.py scan file.c                    # Hybrid scan
  python enhanced_cli.py scan file.c --mode rules       # Rules only
  python enhanced_cli.py scan file.c --mode ml          # ML only
  python enhanced_cli.py scan folder/ --recursive       # Scan directory
  python enhanced_cli.py benchmark diversevul.json      # Benchmark mode
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files for vulnerabilities")
    scan_parser.add_argument("target", help="File or directory to scan")
    scan_parser.add_argument(
        "--mode",
        choices=["rules", "ml", "hybrid"],
        default="hybrid",
        help="Detection mode (default: hybrid)",
    )
    scan_parser.add_argument(
        "--recursive", "-r", action="store_true", help="Scan directory recursively"
    )
    scan_parser.add_argument("--output", "-o", help="Output file for results")
    scan_parser.add_argument(
        "--format",
        choices=["json", "sarif", "text"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--confidence",
        type=float,
        default=0.5,
        help="ML confidence threshold (0.0-1.0, default: 0.5)",
    )
    scan_parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Disable ML features (equivalent to --mode rules)",
    )

    # Benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark against dataset")
    bench_parser.add_argument("dataset", help="Dataset file (JSONL format)")
    bench_parser.add_argument(
        "--samples",
        type=int,
        default=100,
        help="Number of samples to test (default: 100)",
    )
    bench_parser.add_argument(
        "--mode",
        choices=["rules", "ml", "hybrid"],
        default="hybrid",
        help="Detection mode (default: hybrid)",
    )
    bench_parser.add_argument(
        "--balanced",
        action="store_true",
        help="Use balanced sampling (equal vulnerable/safe)",
    )

    # Train command
    train_parser = subparsers.add_parser("train", help="Train ML model")
    train_parser.add_argument("dataset", help="Training dataset (JSONL format)")
    train_parser.add_argument(
        "--samples", type=int, default=10000, help="Training samples (default: 10000)"
    )
    train_parser.add_argument(
        "--epochs", type=int, default=3, help="Training epochs (default: 3)"
    )
    train_parser.add_argument("--output", help="Output model directory")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show system status")

    return parser


def scan_single_file(
    scanner: HybridVulnerabilityScanner, file_path: str, mode: str, confidence: float
) -> Dict:
    """Scan a single file"""
    try:
        result = scanner.scan_file(file_path, mode=mode)
        return result
    except Exception as e:
        return {"file_path": file_path, "error": str(e), "final_assessment": "error"}


def scan_directory(
    scanner: HybridVulnerabilityScanner,
    directory: str,
    recursive: bool,
    mode: str,
    confidence: float,
) -> List[Dict]:
    """Scan directory for source files"""
    results = []
    path = Path(directory)

    # Common source file extensions
    extensions = {
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".java",
        ".py",
        ".php",
        ".js",
        ".ts",
        ".cs",
    }

    if recursive:
        files = [
            f for f in path.rglob("*") if f.suffix.lower() in extensions and f.is_file()
        ]
    else:
        files = [
            f for f in path.iterdir() if f.suffix.lower() in extensions and f.is_file()
        ]

    print(f"🔍 Found {len(files)} source files to scan")

    for i, file_path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] Scanning {file_path.name}...", end=" ")

        result = scan_single_file(scanner, str(file_path), mode, confidence)
        results.append(result)

        # Show quick result
        if result.get("error"):
            print("❌ ERROR")
        elif result.get("final_assessment") == "vulnerable":
            print(f"🔴 VULNERABLE (confidence: {result.get('confidence', 0):.2f})")
        else:
            print("🟢 SAFE")

    return results


def format_results(results: List[Dict], output_format: str) -> str:
    """Format results for output"""
    if output_format == "json":
        return json.dumps(results, indent=2)

    elif output_format == "sarif":
        # Basic SARIF format
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeGuardian",
                            "version": "1.0",
                            "informationUri": "https://github.com/Harsh204k/codeGuardian",
                        }
                    },
                    "results": [],
                }
            ],
        }

        for result in results:
            if result.get("final_assessment") == "vulnerable":
                sarif_result = {
                    "ruleId": "hybrid-vulnerability-detection",
                    "level": (
                        "error" if result.get("confidence", 0) > 0.8 else "warning"
                    ),
                    "message": {
                        "text": f"Potential vulnerability detected (confidence: {result.get('confidence', 0):.2f})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result.get("file_path", "")
                                },
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
                sarif["runs"][0]["results"].append(sarif_result)

        return json.dumps(sarif, indent=2)

    else:  # text format
        output = []
        output.append("=" * 60)
        output.append("🛡️  CODEGUARDIAN HYBRID VULNERABILITY SCAN RESULTS")
        output.append("=" * 60)

        vulnerable_files = [
            r for r in results if r.get("final_assessment") == "vulnerable"
        ]
        safe_files = [r for r in results if r.get("final_assessment") == "safe"]
        error_files = [r for r in results if r.get("final_assessment") == "error"]

        output.append(f"\n📊 SUMMARY:")
        output.append(f"   Total files scanned: {len(results)}")
        output.append(f"   🔴 Vulnerable: {len(vulnerable_files)}")
        output.append(f"   🟢 Safe: {len(safe_files)}")
        output.append(f"   ❌ Errors: {len(error_files)}")

        if vulnerable_files:
            output.append(f"\n🔴 VULNERABLE FILES:")
            for result in vulnerable_files:
                output.append(f"   📄 {result['file_path']}")
                output.append(f"      Confidence: {result.get('confidence', 0):.2f}")
                output.append(
                    f"      Hybrid Score: {result.get('hybrid_score', 0):.2f}"
                )

                if result.get("rule_findings"):
                    output.append(
                        f"      Rule Findings: {len(result['rule_findings'])}"
                    )
                    for finding in result["rule_findings"][:3]:  # Show top 3
                        output.append(
                            f"        - {finding.get('message', 'N/A')} (Line {finding.get('line', '?')})"
                        )

                if result.get("ml_analysis"):
                    output.append(
                        f"      ML Analysis: {result['ml_analysis'].get('explanation', 'N/A')}"
                    )

                output.append("")

        if error_files:
            output.append(f"\n❌ FILES WITH ERRORS:")
            for result in error_files:
                output.append(
                    f"   📄 {result['file_path']}: {result.get('error', 'Unknown error')}"
                )

        return "\n".join(output)


def benchmark_command(args):
    """Run benchmark against dataset"""
    print(f"🏁 BENCHMARKING AGAINST {args.dataset}")
    print(f"   Mode: {args.mode}")
    print(f"   Samples: {args.samples}")

    # Implementation would go here
    print("⚠️  Benchmarking not yet implemented in this demo")


def train_command(args):
    """Train ML model"""
    print(f"🎓 TRAINING ML MODEL")
    print(f"   Dataset: {args.dataset}")
    print(f"   Samples: {args.samples}")

    # Implementation would go here
    print("⚠️  Training command not yet implemented in this demo")
    print("   Use: python quick_train_ml.py")


def status_command(args):
    """Show system status"""
    print("🔧 CODEGUARDIAN SYSTEM STATUS")
    print("=" * 40)

    # Check ML model
    model_path = Path("models")
    ml_models = list(model_path.glob("*codebert*")) if model_path.exists() else []

    print(f"🤖 ML Models: {len(ml_models)} found")
    for model in ml_models[:3]:
        print(f"   - {model.name}")

    # Check rules
    rules_path = Path("rules")
    rule_files = list(rules_path.glob("*.yml")) if rules_path.exists() else []

    print(f"📋 Rule Files: {len(rule_files)} found")
    for rule_file in rule_files:
        print(f"   - {rule_file.name}")

    # Test scanner initialization
    try:
        scanner = HybridVulnerabilityScanner(enable_ml=True)
        print(
            f"✅ Hybrid Scanner: Operational (ML {'enabled' if scanner.ml_enabled else 'disabled'})"
        )
    except Exception as e:
        print(f"❌ Hybrid Scanner: Error - {e}")


def main():
    parser = setup_args()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "scan":
        # Handle scan command
        mode = "rules" if args.no_ml else args.mode

        print(f"🚀 CODEGUARDIAN HYBRID SCANNER")
        print(f"   Target: {args.target}")
        print(f"   Mode: {mode}")
        print(f"   ML Confidence Threshold: {args.confidence}")
        print()

        # Initialize scanner
        try:
            scanner = HybridVulnerabilityScanner(enable_ml=(mode != "rules"))
        except Exception as e:
            print(f"❌ Failed to initialize scanner: {e}")
            return 1

        # Determine if target is file or directory
        target_path = Path(args.target)

        if not target_path.exists():
            print(f"❌ Target not found: {args.target}")
            return 1

        # Scan target
        if target_path.is_file():
            print(f"📄 Scanning single file: {target_path.name}")
            results = [
                scan_single_file(scanner, str(target_path), mode, args.confidence)
            ]
        else:
            print(f"📁 Scanning directory: {target_path}")
            results = scan_directory(
                scanner, str(target_path), args.recursive, mode, args.confidence
            )

        # Format and output results
        formatted_output = format_results(results, args.format)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(formatted_output)
            print(f"\n💾 Results saved to: {args.output}")
        else:
            print(formatted_output)

    elif args.command == "benchmark":
        benchmark_command(args)

    elif args.command == "train":
        train_command(args)

    elif args.command == "status":
        status_command(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
