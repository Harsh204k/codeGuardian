"""
Multi-Analyzer Orchestrator
Batch processes datasets by language and aggregates static analysis results
"""
import json
import csv
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import pandas as pd

from .language_map import get_analyzer_for_language, is_language_supported
from .rule_engine import RuleEngine


logger = logging.getLogger(__name__)


class MultiAnalyzer:
    """
    Orchestrates static analysis across multiple languages and datasets.
    Batches by language for efficiency and aggregates results.
    """
    
    def __init__(self, rules_dir: Path, max_workers: int = 4):
        """
        Initialize multi-analyzer
        
        Args:
            rules_dir: Path to rules directory
            max_workers: Number of parallel workers
        """
        self.rules_dir = Path(rules_dir)
        self.max_workers = max_workers
        self.rule_engine = RuleEngine(rules_dir)
        self.rule_engine.load_all_rules()
        
        logger.info(f"Initialized MultiAnalyzer with {max_workers} workers")
        logger.info(f"Loaded rules for CWEs: {self.rule_engine.get_supported_cwes()}")
    
    def analyze_dataset(self, dataset_path: Path, output_dir: Path, 
                       batch_size: int = 100, incremental_save: bool = True) -> Dict[str, Any]:
        """
        Analyze a complete dataset (JSONL format) with optional incremental saving.
        
        Args:
            dataset_path: Path to input JSONL file
            output_dir: Path to output directory
            batch_size: Number of records to process in each batch
            incremental_save: Save results incrementally per language
            
        Returns:
            Analysis summary statistics
        """
        logger.info(f"Analyzing dataset: {dataset_path}")
        
        # Read dataset
        records = self._load_dataset(dataset_path)
        total_records = len(records)
        
        logger.info(f"Loaded {total_records} records")
        
        # Group by language
        language_groups = self._group_by_language(records)
        
        logger.info(f"Found {len(language_groups)} languages")
        
        # Analyze each language group
        all_results = []
        stats = {
            'total_records': total_records,
            'analyzed': 0,
            'skipped': 0,
            'errors': 0,
            'languages': {},
            'total_vulnerabilities': 0,
            'unique_cwes': set()
        }
        
        # Ensure output directory exists
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for language, lang_records in language_groups.items():
            logger.info(f"Analyzing {len(lang_records)} {language} records...")
            
            if not is_language_supported(language):
                logger.warning(f"Language {language} not supported, skipping")
                stats['skipped'] += len(lang_records)
                continue
            
            results = self._analyze_language_batch(language, lang_records)
            
            # Incremental save per language
            if incremental_save and results:
                self._save_incremental_results(
                    results, output_dir, dataset_path.stem, language
                )
            
            all_results.extend(results)
            
            # Update stats
            lang_stats = self._compute_language_stats(results)
            stats['languages'][language] = lang_stats
            stats['analyzed'] += len(results)
            stats['total_vulnerabilities'] += lang_stats['total_vulnerabilities']
            stats['unique_cwes'].update(lang_stats['unique_cwes'])
        
        # Convert unique_cwes set to list for JSON serialization
        stats['unique_cwes'] = sorted(list(stats['unique_cwes']))
        
        # Save final consolidated results
        self._save_results(all_results, output_dir, dataset_path.stem)
        self._save_stats(stats, output_dir, dataset_path.stem)
        
        logger.info(f"Analysis complete: {stats['analyzed']} records analyzed")
        logger.info(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
        logger.info(f"Unique CWEs: {len(stats['unique_cwes'])}")
        
        return stats
    
    def _save_incremental_results(self, results: List[Dict[str, Any]], 
                                 output_dir: Path, split_name: str, 
                                 language: str) -> None:
        """
        Save results incrementally per language.
        
        Args:
            results: Analysis results
            output_dir: Output directory
            split_name: Dataset split name (train/val/test)
            language: Programming language
        """
        incremental_dir = output_dir / 'incremental'
        incremental_dir.mkdir(parents=True, exist_ok=True)
        
        # Save language-specific results
        jsonl_path = incremental_dir / f"static_analysis_{split_name}_{language}.jsonl"
        with open(jsonl_path, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        logger.debug(f"Saved incremental results for {language} to {jsonl_path}")
    
    def _load_dataset(self, dataset_path: Path) -> List[Dict[str, Any]]:
        """Load dataset from JSONL file"""
        records = []
        
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    records.append(record)
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing line: {e}")
        
        return records
    
    def _group_by_language(self, records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group records by programming language"""
        groups = {}
        
        for record in records:
            language = record.get('language', 'unknown').lower()
            
            if language not in groups:
                groups[language] = []
            
            groups[language].append(record)
        
        return groups
    
    def _analyze_language_batch(self, language: str, 
                                records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of records for a specific language using parallel processing.
        
        Args:
            language: Programming language
            records: List of code records to analyze
            
        Returns:
            List of analysis results
        """
        analyzer = get_analyzer_for_language(language, self.rule_engine)
        
        if not analyzer:
            logger.error(f"Could not create analyzer for {language}")
            return []
        
        results = []
        
        # For small batches, use sequential processing
        if len(records) < 50 or self.max_workers == 1:
            for record in tqdm(records, desc=f"Analyzing {language}", unit="record"):
                try:
                    result = self._analyze_single_record(record, analyzer)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error analyzing record {record.get('id')}: {e}")
            return results
        
        # For larger batches, use parallel processing
        batch_size = max(1, len(records) // (self.max_workers * 4))
        batches = [records[i:i + batch_size] for i in range(0, len(records), batch_size)]
        
        logger.info(f"Processing {len(records)} {language} records in {len(batches)} batches with {self.max_workers} workers")
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit batches
            future_to_batch = {
                executor.submit(self._process_batch_worker, batch, language): i 
                for i, batch in enumerate(batches)
            }
            
            # Collect results with progress bar
            with tqdm(total=len(records), desc=f"Analyzing {language}", unit="record") as pbar:
                for future in as_completed(future_to_batch):
                    try:
                        batch_results = future.result()
                        results.extend(batch_results)
                        pbar.update(len(batch_results))
                    except Exception as e:
                        batch_idx = future_to_batch[future]
                        logger.error(f"Batch {batch_idx} failed: {e}")
                        pbar.update(len(batches[batch_idx]))
        
        return results
    
    @staticmethod
    def _process_batch_worker(batch: List[Dict[str, Any]], language: str) -> List[Dict[str, Any]]:
        """
        Worker function for parallel batch processing.
        This runs in a separate process.
        
        Args:
            batch: Batch of records to process
            language: Programming language
            
        Returns:
            List of analysis results
        """
        # Import here to avoid pickling issues
        from .language_map import get_analyzer_for_language
        from .rule_engine import RuleEngine
        from pathlib import Path
        
        # Create analyzer for this worker
        rules_dir = Path(__file__).parent.parent / 'rules'
        rule_engine = RuleEngine(rules_dir)
        rule_engine.load_all_rules()
        
        analyzer = get_analyzer_for_language(language, rule_engine)
        if not analyzer:
            return []
        
        results = []
        for record in batch:
            try:
                code = record.get('code', '')
                record_id = record.get('id', 'unknown')
                
                if not code:
                    continue
                
                # Perform analysis
                analysis_result = analyzer.analyze(code, record_id)
                
                # Merge with original record
                result = {
                    **record,
                    'static_analysis': analysis_result
                }
                
                results.append(result)
                
            except Exception as e:
                logging.error(f"Error in worker analyzing record {record.get('id')}: {e}")
        
        return results
    
    @staticmethod
    def _analyze_single_record(record: Dict[str, Any], analyzer) -> Optional[Dict[str, Any]]:
        """
        Analyze a single record.
        
        Args:
            record: Code record
            analyzer: Language analyzer instance
            
        Returns:
            Analysis result or None
        """
        code = record.get('code', '')
        record_id = record.get('id', 'unknown')
        
        if not code:
            logger.warning(f"Empty code for record {record_id}")
            return None
        
        # Perform analysis
        analysis_result = analyzer.analyze(code, record_id)
        
        # Merge with original record
        return {
            **record,
            'static_analysis': analysis_result
        }
    
    def _compute_language_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute statistics for language results"""
        stats = {
            'total_records': len(results),
            'total_vulnerabilities': 0,
            'unique_cwes': set(),
            'severity_distribution': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            },
            'avg_complexity': 0.0
        }
        
        complexity_sum = 0
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            
            # Count vulnerabilities
            vuln_count = static_analysis.get('vulnerability_count', 0)
            stats['total_vulnerabilities'] += vuln_count
            
            # Collect CWEs
            cwes = static_analysis.get('detected_cwes', [])
            stats['unique_cwes'].update(cwes)
            
            # Severity distribution
            severity_scores = static_analysis.get('severity_scores', {})
            counts = severity_scores.get('counts', {})
            for severity, count in counts.items():
                if severity in stats['severity_distribution']:
                    stats['severity_distribution'][severity] += count
            
            # Complexity
            metrics = static_analysis.get('static_metrics', {})
            complexity = metrics.get('M15_code_complexity_score', 0)
            complexity_sum += complexity
        
        if len(results) > 0:
            stats['avg_complexity'] = complexity_sum / len(results)
        
        return stats
    
    def _save_results(self, results: List[Dict[str, Any]], 
                     output_dir: Path, split_name: str) -> None:
        """Save analysis results in multiple formats"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save full results as JSONL
        jsonl_path = output_dir / f"static_analysis_{split_name}.jsonl"
        with open(jsonl_path, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        logger.info(f"Saved full results to {jsonl_path}")
        
        # Save static flags as CSV for ML model
        csv_path = output_dir / f"static_flags_{split_name}.csv"
        self._save_static_flags_csv(results, csv_path)
        
        logger.info(f"Saved static flags to {csv_path}")
        
        # Save vulnerability report
        report_path = output_dir / 'logs' / f"analyzer_report_{split_name}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        self._save_vulnerability_report(results, report_path)
        
        logger.info(f"Saved vulnerability report to {report_path}")
    
    def _save_static_flags_csv(self, results: List[Dict[str, Any]], 
                               csv_path: Path) -> None:
        """Save static flags in CSV format for ML model input"""
        rows = []
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            static_flags = static_analysis.get('static_flags', {})
            static_metrics = static_analysis.get('static_metrics', {})
            
            row = {
                'id': result.get('id'),
                'language': result.get('language'),
                'label': result.get('label'),
                
                # Static flags with confidence
                'has_vulnerabilities': static_flags.get('has_vulnerabilities', False),
                'vulnerability_count': static_flags.get('vulnerability_count', 0),
                'critical_count': static_flags.get('critical_count', 0),
                'high_count': static_flags.get('high_count', 0),
                'medium_count': static_flags.get('medium_count', 0),
                'low_count': static_flags.get('low_count', 0),
                'severity_score': static_flags.get('severity_score', 0),
                'max_severity': static_flags.get('max_severity', 'NONE'),
                'static_confidence': static_analysis.get('overall_confidence', 0.0),  # NEW
                
                # Key metrics (M1-M15)
                'M1_cyclomatic_complexity': static_metrics.get('M1_cyclomatic_complexity', 0),
                'M2_nesting_depth': static_metrics.get('M2_nesting_depth', 0),
                'M3_function_call_count': static_metrics.get('M3_function_call_count', 0),
                'M4_lines_of_code': static_metrics.get('M4_lines_of_code', 0),
                'M5_string_literal_count': static_metrics.get('M5_string_literal_count', 0),
                'M6_numeric_literal_count': static_metrics.get('M6_numeric_literal_count', 0),
                'M7_api_call_count': static_metrics.get('M7_api_call_count', 0),
                'M8_dangerous_function_count': static_metrics.get('M8_dangerous_function_count', 0),
                'M9_comment_ratio': static_metrics.get('M9_comment_ratio', 0.0),
                'M10_import_count': static_metrics.get('M10_import_count', 0),
                'M11_variable_count': static_metrics.get('M11_variable_count', 0),
                'M12_conditional_count': static_metrics.get('M12_conditional_count', 0),
                'M13_loop_count': static_metrics.get('M13_loop_count', 0),
                'M14_exception_handling_count': static_metrics.get('M14_exception_handling_count', 0),
                'M15_code_complexity_score': static_metrics.get('M15_code_complexity_score', 0.0),
            }
            
            rows.append(row)
        
        # Write CSV
        df = pd.DataFrame(rows)
        df.to_csv(csv_path, index=False)
    
    def _save_vulnerability_report(self, results: List[Dict[str, Any]], 
                                   report_path: Path) -> None:
        """Save detailed vulnerability report"""
        report = {
            'total_records': len(results),
            'records_with_vulnerabilities': 0,
            'vulnerabilities_by_cwe': {},
            'vulnerabilities_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            },
            'top_vulnerable_records': []
        }
        
        vulnerable_records = []
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            if vulnerabilities:
                report['records_with_vulnerabilities'] += 1
                
                vulnerable_records.append({
                    'id': result.get('id'),
                    'language': result.get('language'),
                    'vuln_count': len(vulnerabilities),
                    'severity_score': static_analysis.get('severity_scores', {}).get('total_score', 0)
                })
            
            # Count by CWE
            for vuln in vulnerabilities:
                cwe_id = vuln.get('cwe_id', 'UNKNOWN')
                if cwe_id not in report['vulnerabilities_by_cwe']:
                    report['vulnerabilities_by_cwe'][cwe_id] = 0
                report['vulnerabilities_by_cwe'][cwe_id] += 1
                
                # Count by severity
                severity = vuln.get('severity', 'INFO')
                if severity in report['vulnerabilities_by_severity']:
                    report['vulnerabilities_by_severity'][severity] += 1
        
        # Top 20 most vulnerable records
        vulnerable_records.sort(key=lambda x: x['severity_score'], reverse=True)
        report['top_vulnerable_records'] = vulnerable_records[:20]
        
        # Save report
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    
    def _save_stats(self, stats: Dict[str, Any], output_dir: Path, 
                   split_name: str) -> None:
        """Save analysis statistics"""
        stats_path = output_dir / 'logs' / f"analysis_stats_{split_name}.json"
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, default=str)
        
        logger.info(f"Saved statistics to {stats_path}")
