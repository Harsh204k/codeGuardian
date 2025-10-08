"""
CodeGuardian Static Analysis - Report Utilities

This module provides utilities for scoring, normalization, CVE mapping,
and report generation for static analysis results.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ReportUtils:
    """
    Utilities for generating reports and scoring static analysis results.
    """
    
    # CWE to OWASP Top 10 mapping
    CWE_TO_OWASP = {
        'CWE-79': 'A03:2021-Injection',
        'CWE-89': 'A03:2021-Injection',
        'CWE-78': 'A03:2021-Injection',
        'CWE-94': 'A03:2021-Injection',
        'CWE-22': 'A01:2021-Broken Access Control',
        'CWE-502': 'A08:2021-Software and Data Integrity Failures',
        'CWE-798': 'A07:2021-Identification and Authentication Failures',
        'CWE-327': 'A02:2021-Cryptographic Failures',
        'CWE-295': 'A02:2021-Cryptographic Failures',
        'CWE-611': 'A05:2021-Security Misconfiguration',
        'CWE-400': 'A04:2021-Insecure Design',
        'CWE-476': 'A04:2021-Insecure Design',
        'CWE-190': 'A04:2021-Insecure Design',
        'CWE-120': 'A03:2021-Injection',
        'CWE-416': 'A04:2021-Insecure Design',
    }
    
    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        'CRITICAL': 10.0,
        'HIGH': 7.0,
        'MEDIUM': 4.0,
        'LOW': 2.0,
        'INFO': 1.0,
    }
    
    # Confidence weights
    CONFIDENCE_WEIGHTS = {
        'HIGH': 1.0,
        'MEDIUM': 0.7,
        'LOW': 0.4,
    }
    
    @staticmethod
    def calculate_risk_score(findings: List[Dict[str, Any]]) -> float:
        """
        Calculate overall risk score based on findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not findings:
            return 0.0
        
        total_score = 0.0
        max_possible = 0.0
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            confidence = finding.get('confidence', 'MEDIUM').upper()
            
            severity_weight = ReportUtils.SEVERITY_WEIGHTS.get(severity, 4.0)
            confidence_weight = ReportUtils.CONFIDENCE_WEIGHTS.get(confidence, 0.7)
            
            total_score += severity_weight * confidence_weight
            max_possible += 10.0  # CRITICAL with HIGH confidence
        
        # Normalize to 0-1 range
        normalized = total_score / max(max_possible, 1.0)
        return round(min(normalized, 1.0), 3)
    
    @staticmethod
    def generate_static_flags(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Generate binary flags for ML model input based on findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary of binary flags
        """
        flags = {}
        
        # CWE-specific flags
        cwe_categories = [
            'CWE-79', 'CWE-89', 'CWE-78', 'CWE-22', 'CWE-327',
            'CWE-295', 'CWE-611', 'CWE-502', 'CWE-798', 'CWE-400',
            'CWE-476', 'CWE-190', 'CWE-120', 'CWE-94', 'CWE-416',
        ]
        
        for cwe in cwe_categories:
            flag_name = f"has_{cwe.lower().replace('-', '_')}"
            flags[flag_name] = 1 if any(f.get('cwe_id') == cwe for f in findings) else 0
        
        # Severity flags
        flags['has_critical'] = 1 if any(f.get('severity') == 'CRITICAL' for f in findings) else 0
        flags['has_high'] = 1 if any(f.get('severity') == 'HIGH' for f in findings) else 0
        flags['has_medium'] = 1 if any(f.get('severity') == 'MEDIUM' for f in findings) else 0
        
        # Confidence flags
        flags['has_high_confidence'] = 1 if any(f.get('confidence') == 'HIGH' for f in findings) else 0
        
        # OWASP flags
        owasp_categories = set(ReportUtils.CWE_TO_OWASP.values())
        for owasp in owasp_categories:
            # Simplify OWASP name for flag
            owasp_key = owasp.split(':')[0].replace('A', 'owasp_a')
            flags[f"has_{owasp_key}"] = 0
        
        for finding in findings:
            cwe_id = finding.get('cwe_id')
            if cwe_id in ReportUtils.CWE_TO_OWASP:
                owasp = ReportUtils.CWE_TO_OWASP[cwe_id]
                owasp_key = owasp.split(':')[0].replace('A', 'owasp_a')
                flags[f"has_{owasp_key}"] = 1
        
        return flags
    
    @staticmethod
    def map_cwe_to_owasp(cwe_id: str) -> Optional[str]:
        """
        Map a CWE ID to OWASP Top 10 category.
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')
            
        Returns:
            OWASP category or None
        """
        return ReportUtils.CWE_TO_OWASP.get(cwe_id)
    
    @staticmethod
    def aggregate_findings_by_cwe(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings by CWE ID.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary mapping CWE ID to list of findings
        """
        by_cwe = defaultdict(list)
        
        for finding in findings:
            cwe_id = finding.get('cwe_id', 'CWE-Unknown')
            by_cwe[cwe_id].append(finding)
        
        return dict(by_cwe)
    
    @staticmethod
    def aggregate_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings by severity level.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary mapping severity to list of findings
        """
        by_severity = defaultdict(list)
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            by_severity[severity].append(finding)
        
        return dict(by_severity)
    
    @staticmethod
    def generate_summary_report(all_findings: Dict[str, Any], output_path: Path):
        """
        Generate a comprehensive summary report.
        
        Args:
            all_findings: Dictionary with all findings data
            output_path: Path to save the report
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_records': 0,
                'total_findings': 0,
                'by_severity': Counter(),
                'by_cwe': Counter(),
                'by_language': Counter(),
                'avg_risk_score': 0.0,
            },
            'top_cwes': [],
            'top_vulnerable_files': [],
            'details': []
        }
        
        total_risk = 0.0
        vulnerable_files = Counter()
        
        for record_id, record_data in all_findings.items():
            report['summary']['total_records'] += 1
            
            findings = record_data.get('findings', [])
            report['summary']['total_findings'] += len(findings)
            
            language = record_data.get('language', 'unknown')
            report['summary']['by_language'][language] += 1
            
            risk_score = record_data.get('risk_score', 0.0)
            total_risk += risk_score
            
            file_path = record_data.get('file_path', 'unknown')
            if findings:
                vulnerable_files[file_path] += len(findings)
            
            # Aggregate by severity and CWE
            for finding in findings:
                severity = finding.get('severity', 'MEDIUM').upper()
                report['summary']['by_severity'][severity] += 1
                
                cwe_id = finding.get('cwe_id', 'CWE-Unknown')
                report['summary']['by_cwe'][cwe_id] += 1
        
        # Calculate average risk score
        if report['summary']['total_records'] > 0:
            report['summary']['avg_risk_score'] = round(
                total_risk / report['summary']['total_records'], 3
            )
        
        # Top CWEs
        report['top_cwes'] = [
            {'cwe_id': cwe, 'count': count}
            for cwe, count in report['summary']['by_cwe'].most_common(10)
        ]
        
        # Top vulnerable files
        report['top_vulnerable_files'] = [
            {'file': file, 'finding_count': count}
            for file, count in vulnerable_files.most_common(10)
        ]
        
        # Convert Counters to dicts for JSON serialization
        report['summary']['by_severity'] = dict(report['summary']['by_severity'])
        report['summary']['by_cwe'] = dict(report['summary']['by_cwe'])
        report['summary']['by_language'] = dict(report['summary']['by_language'])
        
        # Write report
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Summary report saved to {output_path}")
    
    @staticmethod
    def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a finding to standard format.
        
        Args:
            finding: Raw finding dictionary
            
        Returns:
            Normalized finding dictionary
        """
        normalized = {
            'id': finding.get('id', 'unknown'),
            'rule_id': finding.get('rule_id', ''),
            'cwe_id': finding.get('cwe_id', 'CWE-Unknown'),
            'severity': finding.get('severity', 'MEDIUM').upper(),
            'confidence': finding.get('confidence', 'MEDIUM').upper(),
            'message': finding.get('message', ''),
            'line_no': finding.get('line_no', 0),
            'evidence': finding.get('evidence', ''),
            'file_path': finding.get('file_path', ''),
            'language': finding.get('language', ''),
            'remediation': finding.get('remediation', ''),
            'owasp': finding.get('owasp') or ReportUtils.map_cwe_to_owasp(finding.get('cwe_id', '')),
            'tags': finding.get('tags', []),
        }
        
        return normalized
    
    @staticmethod
    def create_jsonl_output(records: List[Dict[str, Any]], output_path: Path):
        """
        Create JSONL output file for pipeline integration.
        
        Args:
            records: List of analysis records
            output_path: Path to save JSONL file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for record in records:
                json.dump(record, f, ensure_ascii=False)
                f.write('\n')
        
        logger.info(f"JSONL output saved to {output_path}")
    
    @staticmethod
    def merge_with_features(static_results_path: Path, 
                          features_path: Path, 
                          output_path: Path):
        """
        Merge static analysis results with feature-engineered data.
        
        Args:
            static_results_path: Path to static analysis JSONL
            features_path: Path to feature-engineered JSONL
            output_path: Path to save merged JSONL
        """
        # Load static results
        static_data = {}
        with open(static_results_path, 'r', encoding='utf-8') as f:
            for line in f:
                record = json.loads(line)
                static_data[record['id']] = record
        
        # Load and merge with features
        merged_records = []
        with open(features_path, 'r', encoding='utf-8') as f:
            for line in f:
                feature_record = json.loads(line)
                record_id = feature_record['id']
                
                # Merge static results if available
                if record_id in static_data:
                    static_record = static_data[record_id]
                    feature_record.update({
                        'static_flags': static_record.get('static_flags', {}),
                        'risk_score': static_record.get('risk_score', 0.0),
                        'findings': static_record.get('findings', []),
                        'detected_cwes': static_record.get('detected_cwes', []),
                    })
                else:
                    # Add empty static data
                    feature_record.update({
                        'static_flags': {},
                        'risk_score': 0.0,
                        'findings': [],
                        'detected_cwes': [],
                    })
                
                merged_records.append(feature_record)
        
        # Save merged data
        ReportUtils.create_jsonl_output(merged_records, output_path)
        logger.info(f"Merged {len(merged_records)} records to {output_path}")
    
    @staticmethod
    def calculate_severity_distribution(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate distribution of findings by severity.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary of severity counts
        """
        distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    @staticmethod
    def format_finding_for_display(finding: Dict[str, Any]) -> str:
        """
        Format a finding for human-readable display.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Formatted string
        """
        return f"""
[{finding.get('severity', 'MEDIUM')}] {finding.get('cwe_id', 'CWE-Unknown')}: {finding.get('message', '')}
  Location: {finding.get('file_path', 'unknown')}:{finding.get('line_no', 0)}
  Evidence: {finding.get('evidence', '')[:100]}...
  Remediation: {finding.get('remediation', 'N/A')}
""".strip()
