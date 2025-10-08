#!/usr/bin/env python3
"""
Enhanced Parallel Multi-Language Analyzer
Phase 3.2: Production-grade parallel processing with language-homogeneous batching
"""

import json
import logging
import multiprocessing
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from tqdm import tqdm
import threading

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Structured finding result"""
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


class EnhancedMultiAnalyzer:
    """
    Enhanced multi-language analyzer with parallel processing capabilities.
    
    Features:
    - ProcessPoolExecutor for true parallelism
    - Language-homogeneous batching for efficiency
    - Progress tracking with tqdm
    - Atomic incremental writes
    - Configurable workers
    - C language support
    """
    
    def __init__(self, max_workers: Optional[int] = None, rule_engine=None):
        """
        Initialize enhanced multi-analyzer
        
        Args:
            max_workers: Number of parallel workers (default: CPU count - 1)
            rule_engine: RuleEngine instance for rule loading
        """
        self.max_workers = max_workers or max(1, multiprocessing.cpu_count() - 1)
        self.rule_engine = rule_engine
        self.analyzers = {}
        self.write_lock = threading.Lock()
        
        # Initialize analyzers lazily
        self._init_analyzers()
        
        logger.info(f"Enhanced MultiAnalyzer initialized with {self.max_workers} workers")
    
    def _init_analyzers(self):
        """Initialize language-specific analyzers"""
        try:
            from .python_analyzer import PythonAnalyzer
            from .java_analyzer import JavaAnalyzer
            from .cpp_analyzer import CppAnalyzer
            from .c_analyzer import CAnalyzer
            from .js_analyzer import JSAnalyzer
            from .php_analyzer import PHPAnalyzer
            from .go_analyzer import GoAnalyzer
            from .ruby_analyzer import RubyAnalyzer
            
            self.analyzers = {
                'python': PythonAnalyzer(self.rule_engine),
                'java': JavaAnalyzer(self.rule_engine),
                'cpp': CppAnalyzer(self.rule_engine),
                'c': CAnalyzer(self.rule_engine),
                'c++': CppAnalyzer(self.rule_engine),
                'javascript': JSAnalyzer(self.rule_engine),
                'js': JSAnalyzer(self.rule_engine),
                'typescript': JSAnalyzer(self.rule_engine),
                'php': PHPAnalyzer(self.rule_engine),
                'go': GoAnalyzer(self.rule_engine),
                'golang': GoAnalyzer(self.rule_engine),
                'ruby': RubyAnalyzer(self.rule_engine),
            }
            
            logger.info(f"Initialized {len(self.analyzers)} language analyzers")
            
        except ImportError as e:
            logger.warning(f"Some analyzers could not be imported: {e}")
    
    def analyze_dataset_parallel(self, dataset_path: Path, output_dir: Path,
                                 batch_size: int = 100) -> Dict[str, Any]:
        """
        Analyze dataset in parallel with language-homogeneous batching.
        
        Args:
            dataset_path: Path to input JSONL dataset
            output_dir: Directory for output files
            batch_size: Records per batch
            
        Returns:
            Statistics dictionary
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load dataset
        logger.info(f"Loading dataset from {dataset_path}")
        records = self._load_dataset(dataset_path)
        
        if not records:
            logger.warning("No records loaded")
            return {'total_records': 0, 'analyzed': 0, 'skipped': 0}
        
        # Group records by language
        by_language = self._group_by_language(records)
        
        logger.info(f"Processing {len(records)} records across {len(by_language)} languages")
        
        # Process each language batch in parallel
        all_results = []
        stats = {
            'total_records': len(records),
            'analyzed': 0,
            'skipped': 0,
            'total_vulnerabilities': 0,
            'unique_cwes': set(),
            'languages': {}
        }
        
        output_jsonl = output_dir / f"{dataset_path.stem}_static_enhanced.jsonl"
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit batches
            futures = {}
            for language, lang_records in by_language.items():
                # Split into batches
                batches = [lang_records[i:i + batch_size] 
                          for i in range(0, len(lang_records), batch_size)]
                
                for batch_idx, batch in enumerate(batches):
                    future = executor.submit(
                        self._analyze_batch_static,
                        language,
                        batch,
                        batch_idx
                    )
                    futures[future] = (language, batch_idx)
            
            # Collect results with progress bar
            desc = "Analyzing batches"
            for future in tqdm(as_completed(futures), total=len(futures), desc=desc):
                language, batch_idx = futures[future]
                
                try:
                    results = future.result()
                    
                    # Update statistics
                    stats['analyzed'] += len(results)
                    all_results.extend(results)
                    
                    # Update language stats
                    if language not in stats['languages']:
                        stats['languages'][language] = {
                            'total_records': 0,
                            'total_vulnerabilities': 0,
                            'avg_confidence': 0.0
                        }
                    
                    for result in results:
                        stats['languages'][language]['total_records'] += 1
                        stats['languages'][language]['total_vulnerabilities'] += result.get('vulnerability_count', 0)
                        stats['total_vulnerabilities'] += result.get('vulnerability_count', 0)
                        stats['unique_cwes'].update(result.get('detected_cwes', []))
                    
                    # Atomic append to output file
                    self._append_results(output_jsonl, results)
                    
                except Exception as e:
                    logger.error(f"Error processing {language} batch {batch_idx}: {e}")
                    stats['skipped'] += len(by_language[language][batch_idx * batch_size:(batch_idx + 1) * batch_size])
        
        # Calculate averages
        for lang_stats in stats['languages'].values():
            if lang_stats['total_records'] > 0:
                lang_stats['avg_confidence'] = (
                    lang_stats['total_vulnerabilities'] / lang_stats['total_records']
                )
        
        stats['unique_cwes'] = list(stats['unique_cwes'])
        
        # Save stats
        stats_file = output_dir / f"{dataset_path.stem}_stats.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        
        logger.info(f"Analysis complete: {stats['analyzed']} analyzed, {stats['skipped']} skipped")
        logger.info(f"Results saved to {output_jsonl}")
        
        return stats
    
    def _analyze_batch_static(self, language: str, records: List[Dict[str, Any]], 
                             batch_idx: int) -> List[Dict[str, Any]]:
        """
        Analyze a batch of records for a single language (worker function).
        
        Args:
            language: Programming language
            records: List of records to analyze
            batch_idx: Batch index for logging
            
        Returns:
            List of analysis results
        """
        results = []
        
        # Get analyzer for this language
        analyzer = self.analyzers.get(language.lower())
        
        if not analyzer:
            logger.warning(f"No analyzer available for {language}")
            # Return empty results
            for record in records:
                results.append({
                    'id': record.get('id', 'unknown'),
                    'language': language,
                    'findings': [],
                    'static_metrics': {},
                    'static_flags': {},
                    'static_confidence': 0.0,
                    'detected_cwes': [],
                    'vulnerability_count': 0
                })
            return results
        
        # Analyze each record
        for record in records:
            try:
                code = record.get('code', '')
                record_id = record.get('id', 'unknown')
                
                if not code:
                    results.append(self._empty_result(record_id, language))
                    continue
                
                # Perform analysis
                result = analyzer.analyze(code, record_id)
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error analyzing {record.get('id', 'unknown')}: {e}")
                results.append(self._empty_result(record.get('id', 'unknown'), language))
        
        return results
    
    def _load_dataset(self, dataset_path: Path) -> List[Dict[str, Any]]:
        """Load JSONL dataset"""
        records = []
        
        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                for line_no, line in enumerate(f, 1):
                    try:
                        record = json.loads(line)
                        records.append(record)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse line {line_no}: {e}")
        except Exception as e:
            logger.error(f"Error loading dataset {dataset_path}: {e}")
        
        return records
    
    def _group_by_language(self, records: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Group records by programming language"""
        by_language = {}
        
        for record in records:
            language = record.get('language', 'unknown').lower()
            
            if language not in by_language:
                by_language[language] = []
            
            by_language[language].append(record)
        
        return by_language
    
    def _append_results(self, output_path: Path, results: List[Dict[str, Any]]):
        """Atomically append results to JSONL file"""
        with self.write_lock:
            with open(output_path, 'a', encoding='utf-8') as f:
                for result in results:
                    f.write(json.dumps(result) + '\n')
    
    def _empty_result(self, record_id: str, language: str) -> Dict[str, Any]:
        """Generate empty result for skipped records"""
        return {
            'id': record_id,
            'language': language,
            'findings': [],
            'static_metrics': {},
            'static_flags': {},
            'static_confidence': 0.0,
            'detected_cwes': [],
            'vulnerability_count': 0,
            'severity_distribution': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
    
    def analyze_single(self, code: str, language: str, record_id: str = "unknown") -> Dict[str, Any]:
        """
        Analyze a single code snippet synchronously.
        
        Args:
            code: Source code
            language: Programming language
            record_id: Record identifier
            
        Returns:
            Analysis result dictionary
        """
        analyzer = self.analyzers.get(language.lower())
        
        if not analyzer:
            logger.warning(f"No analyzer available for {language}")
            return self._empty_result(record_id, language)
        
        try:
            return analyzer.analyze(code, record_id)
        except Exception as e:
            logger.error(f"Error analyzing {record_id}: {e}")
            return self._empty_result(record_id, language)


# Backward compatibility alias
MultiAnalyzer = EnhancedMultiAnalyzer
