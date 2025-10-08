"""
PHP Static Code Analyzer
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class PhpAnalyzer(BaseAnalyzer):
    """Analyzer for PHP code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        self.dangerous_functions = {'eval', 'assert', 'system', 'exec', 'passthru', 'shell_exec', 'unserialize'}
    
    def analyze(self, code: str, record_id: str = None) -> Dict[str, Any]:
        metrics = self.extract_metrics(code)
        vulnerabilities = self.detect_vulnerabilities(code)
        static_flags = self.generate_static_flags(metrics, vulnerabilities)
        severity_scores = self.calculate_severity_score(vulnerabilities)
        detected_cwes = self.map_vulnerabilities_to_cwes(vulnerabilities)
        overall_confidence = self.compute_overall_confidence(vulnerabilities)
        
        return {
            'id': record_id,
            'language': self.language,
            'static_metrics': metrics,
            'detected_cwes': detected_cwes,
            'vulnerabilities': vulnerabilities,
            'static_flags': static_flags,
            'vulnerability_count': len(vulnerabilities),
            'severity_scores': severity_scores,
            'overall_confidence': overall_confidence
        }
    
    def extract_metrics(self, code: str) -> Dict[str, Any]:
        return self.feature_extractor.extract_all_features(code, self.language)
    
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        if self.rule_engine and self.rules:
            metrics = self.extract_metrics(code)
            vulnerabilities.extend(self.rule_engine.execute_all_rules(self.rules, code, metrics))
        vulnerabilities.extend(self._check_sql_injection(code))
        vulnerabilities.extend(self._check_command_injection(code))
        vulnerabilities.extend(self._check_code_injection(code))
        vulnerabilities.extend(self._check_file_inclusion(code))
        return vulnerabilities
    
    def _check_sql_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [
            r'mysql_query\s*\([^)]*\$',
            r'mysqli_query\s*\([^)]*\$',
            r'\$pdo->query\s*\([^)]*\$',
            r'\$wpdb->query\s*\([^)]*\$',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'php_sql_injection',
                    'cwe_id': 'CWE-89',
                    'severity': 'HIGH',
                    'description': 'SQL injection via variable interpolation',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Use prepared statements',
                    'confidence': 'MEDIUM'
                })
        return findings
    
    def _check_command_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [(r'\bexec\s*\(', 'exec()'), (r'\bsystem\s*\(', 'system()'), 
                    (r'\bshell_exec\s*\(', 'shell_exec()'), (r'\bpassthru\s*\(', 'passthru()')]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'php_command_injection',
                    'cwe_id': 'CWE-78',
                    'severity': 'HIGH',
                    'description': f'Command injection: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0),
                    'remediation': 'Avoid shell commands or sanitize input',
                    'confidence': 'HIGH'
                })
        return findings
    
    def _check_code_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [(r'\beval\s*\(', 'eval()'), (r'\bassert\s*\(', 'assert()')]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'php_code_injection',
                    'cwe_id': 'CWE-94',
                    'severity': 'CRITICAL',
                    'description': f'Code injection: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0),
                    'remediation': 'Avoid eval/assert',
                    'confidence': 'HIGH'
                })
        return findings
    
    def _check_file_inclusion(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [
            r'(include|require)(_once)?\s*\([^)]*\$',
            r'file_get_contents\s*\([^)]*\$',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'php_file_inclusion',
                    'cwe_id': 'CWE-98',
                    'severity': 'HIGH',
                    'description': 'File inclusion vulnerability',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Validate file paths',
                    'confidence': 'MEDIUM'
                })
        return findings
