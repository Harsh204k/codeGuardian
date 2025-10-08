#!/usr/bin/env python3
"""
CodeGuardian Static Analysis Pipeline
Main entry point for running static analysis on datasets
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import logging

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.static.utils.rule_loader import RuleLoader
from src.static.utils.code_parser import CodeParser
from src.static.utils.metrics_extractor import MetricsExtractor
from src.static.utils.report_utils import ReportUtils

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class StaticAnalysisPipeline:
    """
    Main pipeline for running static analysis across datasets.
    """
    
    def __init__(self, input_path: Path, output_dir: Path, workers: int = 4):
        """
        Initialize the static analysis pipeline.
        
        Args:
            input_path: Path to input JSONL file
            output_dir: Directory for output files
            workers: Number of parallel workers
        """
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.workers = workers
        self.rule_loader = RuleLoader()
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Language detection mapping
        self.language_map = {
            'python': 'python',
            'java': 'java',
            'cpp': 'cpp',
            'c++': 'cpp',
            'c': 'c',
            'javascript': 'javascript',
            'js': 'javascript',
            'typescript': 'typescript',
            'ts': 'typescript',
            'php': 'php',
            'go': 'go',
            'golang': 'go',
            'ruby': 'ruby',
            'csharp': 'csharp',
            'c#': 'csharp',
        }
    
    def load_dataset(self) -> List[Dict[str, Any]]:
        """
        Load the input JSONL dataset.
        
        Returns:
            List of records
        """
        records = []
        
        logger.info(f"Loading dataset from {self.input_path}")
        
        with open(self.input_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse line {line_no}: {e}")
        
        logger.info(f"Loaded {len(records)} records")
        return records
    
    def analyze_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single code record.
        
        Args:
            record: Input record with 'id', 'language', 'code' fields
            
        Returns:
            Analysis result dictionary
        """
        record_id = record.get('id', 'unknown')
        language = record.get('language', '').lower()
        code = record.get('code', '')
        
        # Normalize language
        language = self.language_map.get(language, language)
        
        if not code:
            return self._empty_result(record_id, language)
        
        try:
            # Load rules for this language
            rules = self.rule_loader.load_rules_for_language(language)
            
            # Extract metrics
            metrics_extractor = MetricsExtractor(language)
            metrics = metrics_extractor.compute_all_metrics_with_score(code)
            
            # Parse code
            code_parser = CodeParser(language)
            parsed = code_parser.parse(code)
            
            # Detect vulnerabilities
            findings = self._detect_vulnerabilities(code, rules, language, record_id)
            
            # Calculate risk score
            risk_score = ReportUtils.calculate_risk_score(findings)
            
            # Generate static flags
            static_flags = ReportUtils.generate_static_flags(findings)
            
            # Extract CWE IDs
            detected_cwes = list(set(f['cwe_id'] for f in findings))
            
            result = {
                'id': record_id,
                'language': language,
                'findings': findings,
                'static_metrics': metrics,
                'static_flags': static_flags,
                'risk_score': risk_score,
                'detected_cwes': detected_cwes,
                'vulnerability_count': len(findings),
                'severity_distribution': ReportUtils.calculate_severity_distribution(findings)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing record {record_id}: {e}")
            return self._empty_result(record_id, language, error=str(e))
    
    def _detect_vulnerabilities(self, code: str, rules: List[Dict[str, Any]], 
                               language: str, record_id: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using loaded rules.
        
        Args:
            code: Source code
            rules: List of rule dictionaries
            language: Programming language
            record_id: Record identifier
            
        Returns:
            List of findings
        """
        findings = []
        
        for rule in rules:
            rule_type = rule.get('type', 'regex')
            
            try:
                if rule_type == 'regex':
                    findings.extend(self._apply_regex_rule(rule, code, record_id, language))
                elif rule_type == 'api_call':
                    findings.extend(self._apply_api_call_rule(rule, code, record_id, language))
                elif rule_type == 'keyword':
                    findings.extend(self._apply_keyword_rule(rule, code, record_id, language))
            except Exception as e:
                logger.debug(f"Error applying rule {rule.get('id')}: {e}")
        
        return findings
    
    def _apply_regex_rule(self, rule: Dict[str, Any], code: str, 
                         record_id: str, language: str) -> List[Dict[str, Any]]:
        """Apply regex-based rule."""
        import re
        findings = []
        pattern = rule.get('pattern', '')
        
        if not pattern:
            return findings
        
        try:
            regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            lines = code.split('\n')
            
            for line_no, line in enumerate(lines, 1):
                if regex.search(line):
                    findings.append({
                        'id': f"{record_id}:{line_no}:{rule['id']}",
                        'rule_id': rule['id'],
                        'cwe_id': rule.get('cwe_id', 'CWE-Unknown'),
                        'severity': rule.get('severity', 'MEDIUM'),
                        'confidence': rule.get('confidence', 'MEDIUM'),
                        'message': rule.get('name', 'Security Issue'),
                        'line_no': line_no,
                        'evidence': line.strip()[:200],
                        'file_path': record_id,
                        'language': language,
                        'remediation': rule.get('remediation', ''),
                        'owasp': rule.get('owasp', ''),
                        'tags': rule.get('tags', [])
                    })
        except re.error:
            pass
        
        return findings
    
    def _apply_api_call_rule(self, rule: Dict[str, Any], code: str,
                            record_id: str, language: str) -> List[Dict[str, Any]]:
        """Apply API call detection rule."""
        import re
        findings = []
        api_names = rule.get('api_names', [])
        
        lines = code.split('\n')
        for line_no, line in enumerate(lines, 1):
            for api_name in api_names:
                pattern = rf'\b{re.escape(api_name)}\s*\('
                if re.search(pattern, line):
                    findings.append({
                        'id': f"{record_id}:{line_no}:{rule['id']}",
                        'rule_id': rule['id'],
                        'cwe_id': rule.get('cwe_id', 'CWE-Unknown'),
                        'severity': rule.get('severity', 'MEDIUM'),
                        'confidence': rule.get('confidence', 'MEDIUM'),
                        'message': f"{rule.get('name', 'API Call')}: {api_name}",
                        'line_no': line_no,
                        'evidence': line.strip()[:200],
                        'file_path': record_id,
                        'language': language,
                        'remediation': rule.get('remediation', ''),
                        'owasp': rule.get('owasp', ''),
                        'tags': rule.get('tags', [])
                    })
        
        return findings
    
    def _apply_keyword_rule(self, rule: Dict[str, Any], code: str,
                           record_id: str, language: str) -> List[Dict[str, Any]]:
        """Apply keyword detection rule."""
        import re
        findings = []
        keywords = rule.get('keywords', [])
        
        lines = code.split('\n')
        for line_no, line in enumerate(lines, 1):
            for keyword in keywords:
                pattern = rf'\b{re.escape(keyword)}\b'
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'id': f"{record_id}:{line_no}:{rule['id']}",
                        'rule_id': rule['id'],
                        'cwe_id': rule.get('cwe_id', 'CWE-Unknown'),
                        'severity': rule.get('severity', 'LOW'),
                        'confidence': rule.get('confidence', 'LOW'),
                        'message': f"{rule.get('name', 'Keyword')}: {keyword}",
                        'line_no': line_no,
                        'evidence': line.strip()[:200],
                        'file_path': record_id,
                        'language': language,
                        'remediation': rule.get('remediation', ''),
                        'owasp': rule.get('owasp', ''),
                        'tags': rule.get('tags', [])
                    })
        
        return findings
    
    def _empty_result(self, record_id: str, language: str, error: str = None) -> Dict[str, Any]:
        """Create an empty result for records that can't be analyzed."""
        return {
            'id': record_id,
            'language': language,
            'findings': [],
            'static_metrics': {},
            'static_flags': {},
            'risk_score': 0.0,
            'detected_cwes': [],
            'vulnerability_count': 0,
            'severity_distribution': {},
            'error': error
        }
    
    def run(self, sample_size: Optional[int] = None) -> Dict[str, Any]:
        """
        Run the static analysis pipeline.
        
        Args:
            sample_size: Optional number of records to sample
            
        Returns:
            Dictionary with pipeline results
        """
        # Load dataset
        records = self.load_dataset()
        
        # Sample if requested
        if sample_size:
            import random
            records = random.sample(records, min(sample_size, len(records)))
            logger.info(f"Sampled {len(records)} records")
        
        # Analyze records in parallel
        results = []
        logger.info(f"Analyzing {len(records)} records with {self.workers} workers")
        
        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.analyze_record, record): record 
                      for record in records}
            
            for future in tqdm(as_completed(futures), total=len(futures), 
                             desc="Analyzing"):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Worker error: {e}")
        
        # Generate outputs
        self._save_results(results)
        
        # Generate summary
        summary = self._generate_summary(results)
        
        return summary
    
    def _save_results(self, results: List[Dict[str, Any]]):
        """Save analysis results to files."""
        # Save JSONL
        jsonl_path = self.output_dir / f"{self.input_path.stem}_static_results.jsonl"
        ReportUtils.create_jsonl_output(results, jsonl_path)
        
        # Save static flags CSV
        csv_path = self.output_dir / f"{self.input_path.stem}_static_flags.csv"
        self._save_flags_csv(results, csv_path)
        
        # Save summary report
        summary_path = self.output_dir / f"{self.input_path.stem}_summary.json"
        all_findings = {r['id']: r for r in results}
        ReportUtils.generate_summary_report(all_findings, summary_path)
        
        logger.info(f"Results saved to {self.output_dir}")
    
    def _save_flags_csv(self, results: List[Dict[str, Any]], output_path: Path):
        """Save static flags as CSV for ML model input."""
        import csv
        
        if not results:
            return
        
        # Collect all flag names
        all_flags = set()
        for result in results:
            all_flags.update(result.get('static_flags', {}).keys())
        
        flag_names = sorted(all_flags)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['id', 'risk_score'] + flag_names)
            writer.writeheader()
            
            for result in results:
                row = {
                    'id': result['id'],
                    'risk_score': result.get('risk_score', 0.0)
                }
                flags = result.get('static_flags', {})
                for flag_name in flag_names:
                    row[flag_name] = flags.get(flag_name, 0)
                
                writer.writerow(row)
        
        logger.info(f"Flags CSV saved to {output_path}")
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate pipeline execution summary."""
        total_findings = sum(r['vulnerability_count'] for r in results)
        avg_risk = sum(r['risk_score'] for r in results) / max(len(results), 1)
        
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for result in results:
            dist = result.get('severity_distribution', {})
            for severity, count in dist.items():
                if severity in severity_counts:
                    severity_counts[severity] += count
        
        summary = {
            'total_records': len(results),
            'total_findings': total_findings,
            'average_risk_score': round(avg_risk, 3),
            'severity_distribution': severity_counts,
            'records_with_vulnerabilities': sum(1 for r in results if r['vulnerability_count'] > 0)
        }
        
        logger.info(f"Analysis complete: {summary}")
        return summary


def main():
    parser = argparse.ArgumentParser(
        description='CodeGuardian Static Analysis Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to input JSONL file (e.g., datasets/processed/train.jsonl)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='datasets/static_results',
        help='Output directory for results (default: datasets/static_results)'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of parallel workers (default: 4)'
    )
    
    parser.add_argument(
        '--sample',
        type=int,
        help='Sample size for testing (optional)'
    )
    
    parser.add_argument(
        '--language',
        type=str,
        help='Filter to specific language (optional)'
    )
    
    parser.add_argument(
        '--quick-test',
        action='store_true',
        help='Run quick test with 100 samples'
    )
    
    args = parser.parse_args()
    
    # Quick test mode
    if args.quick_test:
        args.sample = 100
        logger.info("Running in quick test mode (100 samples)")
    
    # Run pipeline
    pipeline = StaticAnalysisPipeline(
        input_path=args.input,
        output_dir=args.output_dir,
        workers=args.workers
    )
    
    summary = pipeline.run(sample_size=args.sample)
    
    print("\n" + "="*60)
    print("STATIC ANALYSIS COMPLETE")
    print("="*60)
    print(f"Total Records: {summary['total_records']}")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"Average Risk Score: {summary['average_risk_score']}")
    print(f"Records with Vulnerabilities: {summary['records_with_vulnerabilities']}")
    print("\nSeverity Distribution:")
    for severity, count in summary['severity_distribution'].items():
        print(f"  {severity}: {count}")
    print("="*60)


if __name__ == '__main__':
    main()
