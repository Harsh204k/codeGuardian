"""
JavaScript/TypeScript Static Code Analyzer
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzer for JavaScript and TypeScript code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        self.dangerous_functions = {'eval', 'Function', 'setTimeout', 'setInterval', 'innerHTML', 'document.write'}
    
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
        vulnerabilities.extend(self._check_xss(code))
        vulnerabilities.extend(self._check_code_injection(code))
        vulnerabilities.extend(self._check_prototype_pollution(code))
        return vulnerabilities
    
    def _check_xss(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [
            (r'\.innerHTML\s*=', 'innerHTML assignment'),
            (r'document\.write\s*\(', 'document.write()'),
            (r'\.outerHTML\s*=', 'outerHTML assignment'),
            (r'\$\([^)]*\)\.html\s*\(', 'jQuery html()'),
        ]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'js_xss',
                    'cwe_id': 'CWE-79',
                    'severity': 'HIGH',
                    'description': f'XSS vulnerability: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0),
                    'remediation': 'Use textContent or sanitize HTML',
                    'confidence': 'MEDIUM'
                })
        return findings
    
    def _check_code_injection(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        patterns = [(r'\beval\s*\(', 'eval()'), (r'\bFunction\s*\(', 'Function constructor')]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, code):
                findings.append({
                    'rule_id': 'js_code_injection',
                    'cwe_id': 'CWE-94',
                    'severity': 'CRITICAL',
                    'description': f'Code injection: {desc}',
                    'line': code[:match.start()].count('\n') + 1,
                    'matched_text': match.group(0),
                    'remediation': 'Avoid eval and Function constructor',
                    'confidence': 'HIGH'
                })
        return findings
    
    def _check_prototype_pollution(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        pattern = r'\[.*__proto__.*\]|\.constructor\.prototype'
        for match in re.finditer(pattern, code):
            findings.append({
                'rule_id': 'js_prototype_pollution',
                'cwe_id': 'CWE-1321',
                'severity': 'MEDIUM',
                'description': 'Prototype pollution risk',
                'line': code[:match.start()].count('\n') + 1,
                'matched_text': match.group(0)[:50],
                'remediation': 'Validate object properties',
                'confidence': 'LOW'
            })
        return findings
