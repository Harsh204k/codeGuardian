#!/usr/bin/env python3
"""
Explainability Report Generator
Generates comprehensive JSON and Markdown reports for static analysis results
Phase 3.2 - Production-grade reporting
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates explainability reports for static analysis results.
    
    Report Types:
    - JSON: Machine-readable comprehensive report
    - Markdown: Human-readable summary report
    """
    
    def __init__(self):
        """Initialize report generator"""
        pass
    
    def generate_json_report(self, findings_data: List[Dict[str, Any]], 
                            output_path: Path, split_name: str = "unknown") -> Dict[str, Any]:
        """
        Generate comprehensive JSON explainability report.
        
        Args:
            findings_data: List of analysis results (from JSONL)
            output_path: Output file path
            split_name: Dataset split name (train/val/test)
            
        Returns:
            Report dictionary
        """
        logger.info(f"Generating JSON explainability report for {split_name}")
        
        # Collect all findings
        all_findings = []
        for result in findings_data:
            findings = result.get('findings', [])
            all_findings.extend(findings)
        
        # Calculate summary statistics
        summary = self._calculate_summary(findings_data, all_findings)
        
        # Get top CWEs
        top_cwes = self._get_top_cwes(all_findings, n=20)
        
        # Language breakdown
        language_breakdown = self._get_language_breakdown(findings_data)
        
        # Rule hit frequency
        rule_hit_freq = self._get_rule_hit_frequency(all_findings)
        
        # Example hits
        example_hits = self._get_example_hits(all_findings, n=30)
        
        # Severity distribution
        severity_dist = self._get_severity_distribution(all_findings)
        
        # Confidence distribution
        confidence_stats = self._get_confidence_stats(findings_data)
        
        # Build report
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'split_name': split_name,
                'total_records': len(findings_data),
                'version': '3.2'
            },
            'summary': summary,
            'top_cwes': top_cwes,
            'language_breakdown': language_breakdown,
            'rule_hit_frequency': rule_hit_freq,
            'severity_distribution': severity_dist,
            'confidence_statistics': confidence_stats,
            'example_hits': example_hits
        }
        
        # Save report
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to {output_path}")
        
        return report
    
    def generate_markdown_report(self, json_report: Dict[str, Any], 
                                 output_path: Path) -> str:
        """
        Generate human-readable Markdown report from JSON report.
        
        Args:
            json_report: JSON report dictionary
            output_path: Output file path
            
        Returns:
            Markdown content string
        """
        logger.info("Generating Markdown explainability report")
        
        md_lines = []
        
        # Header
        metadata = json_report.get('metadata', {})
        md_lines.append(f"# Static Analysis Explainability Report")
        md_lines.append(f"")
        md_lines.append(f"**Generated:** {metadata.get('generated_at', 'N/A')}")
        md_lines.append(f"**Split:** {metadata.get('split_name', 'N/A')}")
        md_lines.append(f"**Version:** {metadata.get('version', 'N/A')}")
        md_lines.append(f"")
        md_lines.append(f"---")
        md_lines.append(f"")
        
        # Summary
        summary = json_report.get('summary', {})
        md_lines.append(f"## Summary")
        md_lines.append(f"")
        md_lines.append(f"- **Total Records:** {summary.get('total_records', 0):,}")
        md_lines.append(f"- **Total Findings:** {summary.get('total_findings', 0):,}")
        md_lines.append(f"- **Unique CWEs:** {summary.get('unique_cwes', 0)}")
        md_lines.append(f"- **Average Confidence:** {summary.get('avg_confidence', 0):.2f}")
        md_lines.append(f"- **Average Risk Score:** {summary.get('avg_risk_score', 0):.2f}")
        md_lines.append(f"- **Records with Vulnerabilities:** {summary.get('records_with_vulns', 0):,} ({summary.get('vuln_rate', 0):.1f}%)")
        md_lines.append(f"")
        
        # Severity Distribution
        severity_dist = json_report.get('severity_distribution', {})
        md_lines.append(f"## Severity Distribution")
        md_lines.append(f"")
        md_lines.append(f"| Severity | Count | Percentage |")
        md_lines.append(f"|----------|-------|------------|")
        
        total_findings = sum(severity_dist.values())
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_dist.get(severity, 0)
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            md_lines.append(f"| {severity} | {count:,} | {pct:.1f}% |")
        
        md_lines.append(f"")
        
        # Top CWEs
        top_cwes = json_report.get('top_cwes', [])
        md_lines.append(f"## Top CWE Categories")
        md_lines.append(f"")
        md_lines.append(f"| Rank | CWE ID | Count | Severity | Description |")
        md_lines.append(f"|------|--------|-------|----------|-------------|")
        
        for idx, cwe_info in enumerate(top_cwes[:15], 1):
            cwe_id = cwe_info.get('cwe_id', 'Unknown')
            count = cwe_info.get('count', 0)
            severity = cwe_info.get('severity', 'N/A')
            desc = cwe_info.get('description', 'N/A')[:50]
            md_lines.append(f"| {idx} | {cwe_id} | {count:,} | {severity} | {desc}... |")
        
        md_lines.append(f"")
        
        # Language Breakdown
        lang_breakdown = json_report.get('language_breakdown', {})
        md_lines.append(f"## Language Breakdown")
        md_lines.append(f"")
        md_lines.append(f"| Language | Records | Findings | Avg Findings/Record |")
        md_lines.append(f"|----------|---------|----------|---------------------|")
        
        for lang, stats in sorted(lang_breakdown.items(), key=lambda x: x[1].get('findings', 0), reverse=True):
            records = stats.get('records', 0)
            findings = stats.get('findings', 0)
            avg = findings / records if records > 0 else 0
            md_lines.append(f"| {lang} | {records:,} | {findings:,} | {avg:.2f} |")
        
        md_lines.append(f"")
        
        # Top Rules
        rule_freq = json_report.get('rule_hit_frequency', {})
        md_lines.append(f"## Most Triggered Rules")
        md_lines.append(f"")
        md_lines.append(f"| Rank | Rule ID | Hits |")
        md_lines.append(f"|------|---------|------|")
        
        sorted_rules = sorted(rule_freq.items(), key=lambda x: x[1], reverse=True)[:15]
        for idx, (rule_id, count) in enumerate(sorted_rules, 1):
            md_lines.append(f"| {idx} | `{rule_id}` | {count:,} |")
        
        md_lines.append(f"")
        
        # Confidence Statistics
        conf_stats = json_report.get('confidence_statistics', {})
        md_lines.append(f"## Confidence Statistics")
        md_lines.append(f"")
        md_lines.append(f"- **Mean Confidence:** {conf_stats.get('mean', 0):.3f}")
        md_lines.append(f"- **Median Confidence:** {conf_stats.get('median', 0):.3f}")
        md_lines.append(f"- **Min Confidence:** {conf_stats.get('min', 0):.3f}")
        md_lines.append(f"- **Max Confidence:** {conf_stats.get('max', 0):.3f}")
        md_lines.append(f"- **Std Dev:** {conf_stats.get('std_dev', 0):.3f}")
        md_lines.append(f"")
        
        # Example Hits
        examples = json_report.get('example_hits', [])
        md_lines.append(f"## Example Vulnerability Detections")
        md_lines.append(f"")
        
        for idx, example in enumerate(examples[:10], 1):
            md_lines.append(f"### Example {idx}")
            md_lines.append(f"")
            md_lines.append(f"- **ID:** `{example.get('id', 'N/A')}`")
            md_lines.append(f"- **Rule:** `{example.get('rule_id', 'N/A')}`")
            md_lines.append(f"- **CWE:** {example.get('cwe_id', 'N/A')}")
            md_lines.append(f"- **Severity:** {example.get('severity', 'N/A')}")
            md_lines.append(f"- **Confidence:** {example.get('confidence', 0):.2f}")
            md_lines.append(f"- **Evidence:**")
            md_lines.append(f"  ```")
            md_lines.append(f"  {example.get('snippet', 'N/A')}")
            md_lines.append(f"  ```")
            md_lines.append(f"- **Remediation:** {example.get('remediation', 'N/A')}")
            md_lines.append(f"")
        
        # Footer
        md_lines.append(f"---")
        md_lines.append(f"")
        md_lines.append(f"*Report generated by CodeGuardian Static Analyzer Phase 3.2*")
        
        # Join and save
        md_content = "\n".join(md_lines)
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Markdown report saved to {output_path}")
        
        return md_content
    
    def _calculate_summary(self, findings_data: List[Dict], 
                          all_findings: List[Dict]) -> Dict[str, Any]:
        """Calculate summary statistics"""
        total_records = len(findings_data)
        total_findings = len(all_findings)
        
        unique_cwes = set()
        confidences = []
        risk_scores = []
        records_with_vulns = 0
        
        for result in findings_data:
            unique_cwes.update(result.get('detected_cwes', []))
            
            if result.get('static_confidence', 0) > 0:
                confidences.append(result.get('static_confidence', 0))
            
            if result.get('risk_score', 0) > 0:
                risk_scores.append(result.get('risk_score', 0))
            
            if result.get('vulnerability_count', 0) > 0:
                records_with_vulns += 1
        
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        vuln_rate = (records_with_vulns / total_records * 100) if total_records > 0 else 0
        
        return {
            'total_records': total_records,
            'total_findings': total_findings,
            'unique_cwes': len(unique_cwes),
            'avg_confidence': avg_confidence,
            'avg_risk_score': avg_risk,
            'records_with_vulns': records_with_vulns,
            'vuln_rate': vuln_rate
        }
    
    def _get_top_cwes(self, findings: List[Dict], n: int = 20) -> List[Dict[str, Any]]:
        """Get top N CWEs by frequency"""
        cwe_counter = Counter()
        cwe_details = {}
        
        for finding in findings:
            cwe_id = finding.get('cwe_id', 'Unknown')
            cwe_counter[cwe_id] += 1
            
            if cwe_id not in cwe_details:
                cwe_details[cwe_id] = {
                    'severity': finding.get('severity', 'MEDIUM'),
                    'description': finding.get('message', 'N/A')
                }
        
        top_cwes = []
        for cwe_id, count in cwe_counter.most_common(n):
            details = cwe_details.get(cwe_id, {})
            top_cwes.append({
                'cwe_id': cwe_id,
                'count': count,
                'severity': details.get('severity', 'N/A'),
                'description': details.get('description', 'N/A')
            })
        
        return top_cwes
    
    def _get_language_breakdown(self, findings_data: List[Dict]) -> Dict[str, Dict]:
        """Get breakdown by programming language"""
        breakdown = defaultdict(lambda: {'records': 0, 'findings': 0})
        
        for result in findings_data:
            language = result.get('language', 'unknown')
            breakdown[language]['records'] += 1
            breakdown[language]['findings'] += result.get('vulnerability_count', 0)
        
        return dict(breakdown)
    
    def _get_rule_hit_frequency(self, findings: List[Dict]) -> Dict[str, int]:
        """Get frequency of rule hits"""
        rule_counter = Counter()
        
        for finding in findings:
            rule_id = finding.get('rule_id', 'unknown')
            rule_counter[rule_id] += 1
        
        return dict(rule_counter)
    
    def _get_severity_distribution(self, findings: List[Dict]) -> Dict[str, int]:
        """Get distribution of findings by severity"""
        severity_counter = Counter()
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            severity_counter[severity] += 1
        
        return dict(severity_counter)
    
    def _get_confidence_stats(self, findings_data: List[Dict]) -> Dict[str, float]:
        """Calculate confidence statistics"""
        confidences = [
            result.get('static_confidence', 0)
            for result in findings_data
            if result.get('static_confidence', 0) > 0
        ]
        
        if not confidences:
            return {
                'mean': 0.0,
                'median': 0.0,
                'min': 0.0,
                'max': 0.0,
                'std_dev': 0.0
            }
        
        confidences.sort()
        n = len(confidences)
        
        mean = sum(confidences) / n
        median = confidences[n // 2] if n % 2 == 1 else (confidences[n // 2 - 1] + confidences[n // 2]) / 2
        std_dev = (sum((x - mean) ** 2 for x in confidences) / n) ** 0.5
        
        return {
            'mean': mean,
            'median': median,
            'min': min(confidences),
            'max': max(confidences),
            'std_dev': std_dev
        }
    
    def _get_example_hits(self, findings: List[Dict], n: int = 30) -> List[Dict[str, Any]]:
        """Get example vulnerability hits"""
        # Sort by confidence and severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.get('severity', 'MEDIUM'), 2),
                -f.get('confidence', 0)
            )
        )
        
        examples = []
        for finding in sorted_findings[:n]:
            examples.append({
                'id': finding.get('id', 'N/A'),
                'rule_id': finding.get('rule_id', 'N/A'),
                'cwe_id': finding.get('cwe_id', 'N/A'),
                'severity': finding.get('severity', 'N/A'),
                'confidence': finding.get('confidence', 0),
                'snippet': finding.get('evidence', 'N/A'),
                'remediation': finding.get('remediation', 'N/A')
            })
        
        return examples
