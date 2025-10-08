#!/usr/bin/env python3
"""
CodeGuardian Enhanced Static Analysis Pipeline (Phase 3.2)
===========================================================

Enhanced pipeline with:
- C language support via CAnalyzer
- Parallel processing via EnhancedMultiAnalyzer
- Explainability reports (JSON + Markdown)
- Confidence scoring with severity weighting
- Production-grade error handling

Usage:
    python src/static/pipeline/run_static_pipeline_enhanced.py \
        --input datasets/processed/train.jsonl \
        --output datasets/static_results/train_static_enhanced.jsonl \
        --reports outputs/reports \
        --max-workers 7

Author: CodeGuardian Team
Version: 3.2.0 (Phase 3.2)
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static.analyzers.multi_analyzer_enhanced import EnhancedMultiAnalyzer
from src.static.analyzers.rule_engine import RuleEngine
from src.static.utils.report_generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_enhanced_static_analysis(
    input_path: str,
    output_path: str,
    reports_dir: Optional[str] = None,
    max_workers: Optional[int] = None,
    split_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run enhanced static analysis with Phase 3.2 components.
    
    Args:
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file
        reports_dir: Directory for explainability reports (optional)
        max_workers: Maximum number of parallel workers (default: CPU count - 1)
        split_name: Name of the split (train/val/test) for report naming
        
    Returns:
        Summary statistics dictionary
    """
    logger.info("="*70)
    logger.info("CodeGuardian Enhanced Static Analysis Pipeline (Phase 3.2)")
    logger.info("="*70)
    
    # Validate inputs
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Create output directory
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Infer split name from input path if not provided
    if split_name is None:
        split_name = input_file.stem  # e.g., 'train' from 'train.jsonl'
    
    logger.info(f"Input: {input_path}")
    logger.info(f"Output: {output_path}")
    logger.info(f"Split: {split_name}")
    logger.info(f"Workers: {max_workers or 'auto (CPU count - 1)'}")
    
    # Step 1: Load rule engine
    logger.info("\n[1/4] Loading rule engine...")
    rule_engine = RuleEngine()
    rule_engine.load_all_rules()
    
    supported_languages = rule_engine.get_supported_languages()
    logger.info(f"Loaded rules for {len(supported_languages)} languages: {', '.join(supported_languages)}")
    
    # Step 2: Initialize enhanced multi-analyzer
    logger.info("\n[2/4] Initializing enhanced multi-analyzer...")
    analyzer = EnhancedMultiAnalyzer(
        rule_engine=rule_engine,
        max_workers=max_workers
    )
    
    # Step 3: Run parallel analysis
    logger.info("\n[3/4] Running parallel static analysis...")
    logger.info("This may take several minutes depending on dataset size...")
    
    try:
        analyzer.analyze_dataset_parallel(
            input_path=str(input_file),
            output_path=str(output_file)
        )
        logger.info(f"✓ Analysis complete! Results saved to: {output_path}")
    except Exception as e:
        logger.error(f"✗ Analysis failed: {e}")
        raise
    
    # Step 4: Generate explainability reports
    if reports_dir:
        logger.info("\n[4/4] Generating explainability reports...")
        reports_path = Path(reports_dir)
        reports_path.mkdir(parents=True, exist_ok=True)
        
        json_report_path = reports_path / f"explain_{split_name}.json"
        md_report_path = reports_path / f"explain_{split_name}.md"
        
        try:
            # Load analysis results
            logger.info(f"Loading results from {output_path}...")
            findings_data = []
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        findings_data.append(json.loads(line))
            
            logger.info(f"Loaded {len(findings_data)} analyzed records")
            
            # Generate reports
            report_gen = ReportGenerator()
            
            logger.info(f"Generating JSON report: {json_report_path}")
            json_report = report_gen.generate_json_report(
                findings_data=findings_data,
                output_path=str(json_report_path),
                split_name=split_name
            )
            
            logger.info(f"Generating Markdown report: {md_report_path}")
            report_gen.generate_markdown_report(
                json_report=json_report,
                output_path=str(md_report_path)
            )
            
            logger.info(f"✓ Reports generated successfully!")
            logger.info(f"  - JSON: {json_report_path}")
            logger.info(f"  - Markdown: {md_report_path}")
            
            # Return summary from JSON report
            summary = json_report.get('summary', {})
            
        except Exception as e:
            logger.error(f"✗ Report generation failed: {e}")
            # Don't raise - analysis still succeeded
            summary = {'error': str(e)}
    else:
        logger.info("\n[4/4] Skipping explainability reports (no --reports specified)")
        
        # Calculate basic summary
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                findings_data = [json.loads(line) for line in f if line.strip()]
            
            total_records = len(findings_data)
            total_findings = sum(r.get('vulnerability_count', 0) for r in findings_data)
            records_with_vulns = sum(1 for r in findings_data if r.get('vulnerability_count', 0) > 0)
            
            summary = {
                'total_records': total_records,
                'total_findings': total_findings,
                'records_with_vulnerabilities': records_with_vulns
            }
        except Exception as e:
            logger.warning(f"Could not calculate summary: {e}")
            summary = {}
    
    logger.info("\n" + "="*70)
    logger.info("ENHANCED STATIC ANALYSIS COMPLETE")
    logger.info("="*70)
    
    if summary:
        logger.info(f"Total Records: {summary.get('total_records', 'N/A')}")
        logger.info(f"Total Findings: {summary.get('total_findings', 'N/A')}")
        logger.info(f"Records with Vulnerabilities: {summary.get('records_with_vulnerabilities', 'N/A')}")
        
        if 'unique_cwes' in summary:
            logger.info(f"Unique CWEs Detected: {summary['unique_cwes']}")
        if 'average_confidence' in summary:
            logger.info(f"Average Confidence: {summary['average_confidence']:.3f}")
        if 'average_risk_score' in summary:
            logger.info(f"Average Risk Score: {summary['average_risk_score']:.3f}")
    
    logger.info("="*70)
    
    return summary


def main():
    parser = argparse.ArgumentParser(
        description='CodeGuardian Enhanced Static Analysis Pipeline (Phase 3.2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze with explainability reports
  python src/static/pipeline/run_static_pipeline_enhanced.py \\
      --input datasets/processed/train.jsonl \\
      --output datasets/static_results/train_static_enhanced.jsonl \\
      --reports outputs/reports \\
      --split train

  # Analyze without reports
  python src/static/pipeline/run_static_pipeline_enhanced.py \\
      --input datasets/processed/val.jsonl \\
      --output datasets/static_results/val_static_enhanced.jsonl

  # Analyze with custom worker count
  python src/static/pipeline/run_static_pipeline_enhanced.py \\
      --input datasets/processed/test.jsonl \\
      --output datasets/static_results/test_static_enhanced.jsonl \\
      --reports outputs/reports \\
      --max-workers 4 \\
      --split test
        """
    )
    
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to input JSONL file (e.g., datasets/processed/train.jsonl)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Path to output JSONL file (e.g., datasets/static_results/train_static_enhanced.jsonl)'
    )
    
    parser.add_argument(
        '--reports',
        type=str,
        help='Directory for explainability reports (e.g., outputs/reports)'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        help='Maximum number of parallel workers (default: CPU count - 1)'
    )
    
    parser.add_argument(
        '--split',
        type=str,
        help='Split name for report generation (train/val/test, auto-detected if not provided)'
    )
    
    args = parser.parse_args()
    
    try:
        summary = run_enhanced_static_analysis(
            input_path=args.input,
            output_path=args.output,
            reports_dir=args.reports,
            max_workers=args.max_workers,
            split_name=args.split
        )
        
        # Exit successfully
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
