"""
Ruby Static Code Analyzer
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class RubyAnalyzer(BaseAnalyzer):
    """Analyzer for Ruby code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        self.dangerous_functions = {'eval', 'exec', 'system', 'send', 'instance_eval', 'class_eval', 'Marshal.load'}
    
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
        vulnerabilities.extend(self._check_code_injection(code))
        vulnerabilities.extend(self._check_sql_injection(code))
        vulnerabilities.extend(self._check_command_injection(code))
        return vulnerabilities
    
    def _check_code_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [(r'\beval\s*\(', 'eval()'), (r'\binstance_eval\s*\(', 'instance_eval()'), 
                    (r'\bclass_eval\s*\(', 'class_eval()'), (r'\.send\s*\(', 'send()')]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'ruby_code_injection',
                    'cwe_id': 'CWE-94',
                    'severity': 'CRITICAL',
                    'description': f'Code injection: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0),
                    'remediation': 'Avoid eval and dynamic execution',
                    'confidence': 'HIGH'
                })
        return findings
    
    def _check_sql_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [
            r'\.execute\s*\([^)]*#\{',
            r'\.find_by_sql\s*\([^)]*#\{',
            r'\.where\s*\([^)]*#\{',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'ruby_sql_injection',
                    'cwe_id': 'CWE-89',
                    'severity': 'HIGH',
                    'description': 'SQL injection via string interpolation',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Use parameterized queries',
                    'confidence': 'MEDIUM'
                })
        return findings
    
    def _check_command_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [(r'\bsystem\s*\(', 'system()'), (r'\bexec\s*\(', 'exec()'), (r'`[^`]*#\{', 'backtick execution')]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'ruby_command_injection',
                    'cwe_id': 'CWE-78',
                    'severity': 'HIGH',
                    'description': f'Command injection: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Validate command inputs',
                    'confidence': 'MEDIUM'
                })
        return findings
