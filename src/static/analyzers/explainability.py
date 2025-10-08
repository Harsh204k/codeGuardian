"""
Explainability Report Generator for Static Analysis
Generates detailed explainability metrics, CWE analysis, and confidence histograms
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import Counter, defaultdict
import statistics

logger = logging.getLogger(__name__)


class ExplainabilityGenerator:
    """
    Generates explainability reports for static analysis results.
    
    Provides insights into:
    - Top CWEs detected per language
    - Rule hit frequency and confidence distribution
    - Most vulnerable functions/records
    - Aggregate statistics and precision proxies
    """
    
    def __init__(self):
        """Initialize explainability generator."""
        pass
    
    def generate_report(self, results: List[Dict[str, Any]], 
                       split_name: str = "train") -> Dict[str, Any]:
        """
        Generate comprehensive explainability report.
        
        Args:
            results: List of analysis results
            split_name: Dataset split name
            
        Returns:
            Explainability report dictionary
        """
        logger.info(f"Generating explainability report for {split_name} split...")
        
        report = {
            'split': split_name,
            'summary': self._generate_summary(results),
            'cwe_analysis': self._analyze_cwes(results),
            'language_breakdown': self._analyze_by_language(results),
            'confidence_analysis': self._analyze_confidence(results),
            'severity_distribution': self._analyze_severity(results),
            'top_vulnerable_functions': self._find_top_vulnerable(results, top_n=20),
            'rule_effectiveness': self._analyze_rule_effectiveness(results),
            'precision_proxy': self._compute_precision_proxy(results),
            'examples': self._extract_examples(results, max_examples=10)
        }
        
        logger.info(f"Explainability report generated with {len(report)} sections")
        
        return report
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overall summary statistics."""
        total_records = len(results)
        records_with_vulns = 0
        total_vulnerabilities = 0
        total_rules_triggered = 0
        confidence_scores = []
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            if vulnerabilities:
                records_with_vulns += 1
                total_vulnerabilities += len(vulnerabilities)
            
            # Count unique rules triggered
            rule_ids = set(v.get('rule_id') for v in vulnerabilities if v.get('rule_id'))
            total_rules_triggered += len(rule_ids)
            
            # Collect confidence scores
            overall_conf = static_analysis.get('overall_confidence', 0.0)
            if overall_conf > 0:
                confidence_scores.append(overall_conf)
        
        avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0.0
        median_confidence = statistics.median(confidence_scores) if confidence_scores else 0.0
        
        return {
            'total_records': total_records,
            'records_with_vulnerabilities': records_with_vulns,
            'vulnerability_rate': round(records_with_vulns / total_records, 3) if total_records > 0 else 0.0,
            'total_vulnerabilities': total_vulnerabilities,
            'avg_vulnerabilities_per_record': round(total_vulnerabilities / total_records, 2) if total_records > 0 else 0.0,
            'total_rules_triggered': total_rules_triggered,
            'avg_confidence': round(avg_confidence, 3),
            'median_confidence': round(median_confidence, 3),
            'confidence_std_dev': round(statistics.stdev(confidence_scores), 3) if len(confidence_scores) > 1 else 0.0
        }
    
    def _analyze_cwes(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze CWE distribution and frequency."""
        cwe_counter = Counter()
        cwe_confidences = defaultdict(list)
        cwe_severities = defaultdict(list)
        cwe_languages = defaultdict(set)
        
        for result in results:
            language = result.get('language', 'unknown')
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                cwe_id = vuln.get('cwe_id', 'UNKNOWN')
                cwe_counter[cwe_id] += 1
                cwe_languages[cwe_id].add(language)
                
                # Collect confidence
                conf = vuln.get('confidence', 0.5)
                if isinstance(conf, str):
                    conf = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(conf.lower(), 0.5)
                cwe_confidences[cwe_id].append(conf)
                
                # Collect severity
                severity = vuln.get('severity', 'medium')
                cwe_severities[cwe_id].append(severity)
        
        # Top CWEs
        top_cwes = []
        for cwe_id, count in cwe_counter.most_common(20):
            avg_conf = statistics.mean(cwe_confidences[cwe_id]) if cwe_confidences[cwe_id] else 0.0
            
            # Most common severity
            severity_counts = Counter(cwe_severities[cwe_id])
            most_common_severity = severity_counts.most_common(1)[0][0] if severity_counts else 'medium'
            
            top_cwes.append({
                'cwe_id': cwe_id,
                'count': count,
                'avg_confidence': round(avg_conf, 3),
                'most_common_severity': most_common_severity,
                'languages': sorted(list(cwe_languages[cwe_id]))
            })
        
        return {
            'unique_cwes': len(cwe_counter),
            'total_cwe_instances': sum(cwe_counter.values()),
            'top_cwes': top_cwes,
            'cwe_coverage': sorted(list(cwe_counter.keys()))
        }
    
    def _analyze_by_language(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze results broken down by programming language."""
        language_stats = defaultdict(lambda: {
            'total_records': 0,
            'records_with_vulns': 0,
            'total_vulns': 0,
            'unique_cwes': set(),
            'avg_confidence': [],
            'severity_counts': Counter()
        })
        
        for result in results:
            language = result.get('language', 'unknown').lower()
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            language_stats[language]['total_records'] += 1
            
            if vulnerabilities:
                language_stats[language]['records_with_vulns'] += 1
                language_stats[language]['total_vulns'] += len(vulnerabilities)
                
                # Collect CWEs
                for vuln in vulnerabilities:
                    cwe_id = vuln.get('cwe_id')
                    if cwe_id:
                        language_stats[language]['unique_cwes'].add(cwe_id)
                    
                    severity = vuln.get('severity', 'medium')
                    language_stats[language]['severity_counts'][severity] += 1
                
                # Confidence
                overall_conf = static_analysis.get('overall_confidence', 0.0)
                if overall_conf > 0:
                    language_stats[language]['avg_confidence'].append(overall_conf)
        
        # Format output
        breakdown = {}
        for language, stats in language_stats.items():
            avg_conf = statistics.mean(stats['avg_confidence']) if stats['avg_confidence'] else 0.0
            
            breakdown[language] = {
                'total_records': stats['total_records'],
                'records_with_vulnerabilities': stats['records_with_vulns'],
                'vulnerability_rate': round(stats['records_with_vulns'] / stats['total_records'], 3) if stats['total_records'] > 0 else 0.0,
                'total_vulnerabilities': stats['total_vulns'],
                'unique_cwes': len(stats['unique_cwes']),
                'avg_confidence': round(avg_conf, 3),
                'severity_distribution': dict(stats['severity_counts'])
            }
        
        return breakdown
    
    def _analyze_confidence(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze confidence score distribution."""
        all_confidences = []
        vuln_confidences = []
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            overall_conf = static_analysis.get('overall_confidence', 0.0)
            
            if overall_conf > 0:
                all_confidences.append(overall_conf)
            
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                conf = vuln.get('confidence', 0.5)
                if isinstance(conf, str):
                    conf = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(conf.lower(), 0.5)
                vuln_confidences.append(conf)
        
        # Confidence histogram (bins: 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0)
        histogram = self._create_histogram(all_confidences, bins=5)
        
        return {
            'total_confidence_scores': len(all_confidences),
            'avg_overall_confidence': round(statistics.mean(all_confidences), 3) if all_confidences else 0.0,
            'median_confidence': round(statistics.median(all_confidences), 3) if all_confidences else 0.0,
            'confidence_histogram': histogram,
            'avg_vulnerability_confidence': round(statistics.mean(vuln_confidences), 3) if vuln_confidences else 0.0,
            'high_confidence_count': sum(1 for c in all_confidences if c >= 0.8),
            'low_confidence_count': sum(1 for c in all_confidences if c < 0.5)
        }
    
    def _analyze_severity(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze severity distribution."""
        severity_counter = Counter()
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'medium')
                if isinstance(severity, str):
                    severity = severity.lower()
                severity_counter[severity] += 1
        
        total = sum(severity_counter.values())
        
        distribution = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counter.get(severity, 0)
            distribution[severity] = {
                'count': count,
                'percentage': round(count / total * 100, 2) if total > 0 else 0.0
            }
        
        return distribution
    
    def _find_top_vulnerable(self, results: List[Dict[str, Any]], 
                            top_n: int = 20) -> List[Dict[str, Any]]:
        """Find top N most vulnerable functions/records."""
        vulnerable_records = []
        
        for result in results:
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            if not vulnerabilities:
                continue
            
            vuln_count = len(vulnerabilities)
            overall_conf = static_analysis.get('overall_confidence', 0.0)
            
            # Compute vulnerability score (count * confidence)
            vuln_score = vuln_count * overall_conf
            
            vulnerable_records.append({
                'id': result.get('id', 'unknown'),
                'language': result.get('language', 'unknown'),
                'function_name': result.get('func_name', 'N/A'),
                'vulnerability_count': vuln_count,
                'confidence': overall_conf,
                'vulnerability_score': round(vuln_score, 3),
                'cwes': list(set(v.get('cwe_id') for v in vulnerabilities if v.get('cwe_id'))),
                'max_severity': max((v.get('severity', 'low') for v in vulnerabilities), 
                                   key=lambda s: {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(s, 0))
            })
        
        # Sort by vulnerability score
        vulnerable_records.sort(key=lambda x: x['vulnerability_score'], reverse=True)
        
        return vulnerable_records[:top_n]
    
    def _analyze_rule_effectiveness(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze which rules are most effective."""
        rule_stats = defaultdict(lambda: {
            'hit_count': 0,
            'avg_confidence': [],
            'cwes': set(),
            'languages': set()
        })
        
        for result in results:
            language = result.get('language', 'unknown')
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                rule_id = vuln.get('rule_id', 'unknown')
                cwe_id = vuln.get('cwe_id')
                
                rule_stats[rule_id]['hit_count'] += 1
                rule_stats[rule_id]['languages'].add(language)
                
                if cwe_id:
                    rule_stats[rule_id]['cwes'].add(cwe_id)
                
                conf = vuln.get('confidence', 0.5)
                if isinstance(conf, str):
                    conf = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(conf.lower(), 0.5)
                rule_stats[rule_id]['avg_confidence'].append(conf)
        
        # Format top rules
        top_rules = []
        for rule_id, stats in sorted(rule_stats.items(), 
                                     key=lambda x: x[1]['hit_count'], 
                                     reverse=True)[:30]:
            avg_conf = statistics.mean(stats['avg_confidence']) if stats['avg_confidence'] else 0.0
            
            top_rules.append({
                'rule_id': rule_id,
                'hit_count': stats['hit_count'],
                'avg_confidence': round(avg_conf, 3),
                'unique_cwes': len(stats['cwes']),
                'languages': sorted(list(stats['languages']))
            })
        
        return {
            'total_rules_used': len(rule_stats),
            'total_rule_hits': sum(s['hit_count'] for s in rule_stats.values()),
            'top_rules': top_rules
        }
    
    def _compute_precision_proxy(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute precision proxy metrics.
        Uses ground truth labels if available.
        """
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for result in results:
            ground_truth = result.get('label', -1)  # 1 = vulnerable, 0 = safe
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            predicted_vulnerable = len(vulnerabilities) > 0
            
            if ground_truth == 1:  # Actually vulnerable
                if predicted_vulnerable:
                    true_positives += 1
                else:
                    false_negatives += 1
            elif ground_truth == 0:  # Actually safe
                if predicted_vulnerable:
                    false_positives += 1
                else:
                    true_negatives += 1
        
        total_with_labels = true_positives + false_positives + true_negatives + false_negatives
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            'records_with_labels': total_with_labels,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'note': 'Metrics based on ground truth labels where available'
        }
    
    def _extract_examples(self, results: List[Dict[str, Any]], 
                         max_examples: int = 10) -> List[Dict[str, Any]]:
        """Extract example vulnerability detections."""
        examples = []
        
        # Get diverse examples (different CWEs and languages)
        cwe_seen = set()
        lang_seen = set()
        
        for result in results:
            if len(examples) >= max_examples:
                break
            
            language = result.get('language', 'unknown')
            static_analysis = result.get('static_analysis', {})
            vulnerabilities = static_analysis.get('vulnerabilities', [])
            
            if not vulnerabilities:
                continue
            
            # Pick first vulnerability
            vuln = vulnerabilities[0]
            cwe_id = vuln.get('cwe_id', 'UNKNOWN')
            
            # Prefer diverse examples
            if cwe_id in cwe_seen and language in lang_seen:
                continue
            
            cwe_seen.add(cwe_id)
            lang_seen.add(language)
            
            conf = vuln.get('confidence', 0.5)
            if isinstance(conf, str):
                conf = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(conf.lower(), 0.5)
            
            examples.append({
                'id': result.get('id', 'unknown'),
                'language': language,
                'cwe_id': cwe_id,
                'rule_id': vuln.get('rule_id', 'unknown'),
                'severity': vuln.get('severity', 'medium'),
                'confidence': conf,
                'description': vuln.get('description', '')[:200],  # Truncate
                'line': vuln.get('line', 0)
            })
        
        return examples
    
    @staticmethod
    def _create_histogram(values: List[float], bins: int = 5) -> Dict[str, int]:
        """Create histogram from values."""
        if not values:
            return {}
        
        bin_size = 1.0 / bins
        histogram = {}
        
        for i in range(bins):
            lower = i * bin_size
            upper = (i + 1) * bin_size
            label = f"{lower:.1f}-{upper:.1f}"
            count = sum(1 for v in values if lower <= v < upper)
            histogram[label] = count
        
        # Handle edge case for 1.0
        if values:
            last_label = list(histogram.keys())[-1]
            histogram[last_label] += sum(1 for v in values if v == 1.0)
        
        return histogram
    
    def save_report(self, report: Dict[str, Any], output_path: Path) -> None:
        """
        Save explainability report to file.
        
        Args:
            report: Report dictionary
            output_path: Output file path
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Explainability report saved to {output_path}")
