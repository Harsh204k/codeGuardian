"""
Python Static Code Analyzer
Specialized analyzer for Python vulnerability detection
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__', 'input',
            'pickle.loads', 'yaml.load', 'marshal.loads',
            'os.system', 'subprocess.call', 'subprocess.Popen',
            'open'
        }
        
        self.security_apis = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\b__import__\s*\(',
            r'\bpickle\.loads?\s*\(',
            r'\byaml\.load\s*\(',
            r'\bos\.system\s*\(',
            r'\bsubprocess\.',
            r'\bsql\s*=',
        ]
    
    def analyze(self, code: str, record_id: str = None) -> Dict[str, Any]:
        """Perform complete Python static analysis"""
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
        """Extract all static metrics for Python code"""
        return self.feature_extractor.extract_all_features(code, self.language)
    
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """Detect Python specific vulnerabilities"""
        vulnerabilities = []
        
        if self.rule_engine and self.rules:
            metrics = self.extract_metrics(code)
            vulnerabilities.extend(
                self.rule_engine.execute_all_rules(self.rules, code, metrics)
            )
        
        vulnerabilities.extend(self._check_code_injection(code))
        vulnerabilities.extend(self._check_sql_injection(code))
        vulnerabilities.extend(self._check_deserialization(code))
        vulnerabilities.extend(self._check_path_traversal(code))
        vulnerabilities.extend(self._check_xxe(code))
        
        return vulnerabilities
    
    def _check_code_injection(self, code: str) -> List[Dict[str, Any]]:
        """Detect code injection via eval/exec (CWE-94)"""
        findings = []
        patterns = [
            (r'\beval\s*\(', 'eval() with user input'),
            (r'\bexec\s*\(', 'exec() with user input'),
            (r'\bcompile\s*\(', 'compile() with user input'),
            (r'\b__import__\s*\(', '__import__() can be dangerous'),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'python_code_injection',
                    'cwe_id': 'CWE-94',
                    'severity': 'CRITICAL',
                    'description': f'Code injection risk: {desc}',
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': 'Avoid eval/exec; use ast.literal_eval for safe evaluation',
                    'confidence': 'HIGH'
                })
        
        return findings
    
    def _check_sql_injection(self, code: str) -> List[Dict[str, Any]]:
        """Detect SQL injection vulnerabilities (CWE-89)"""
        findings = []
        
        # String formatting in SQL queries
        patterns = [
            r'(execute|cursor\.execute)\s*\([^)]*%[^)]*\)',
            r'(execute|cursor\.execute)\s*\([^)]*\.format\(',
            r'(execute|cursor\.execute)\s*\([^)]*\+',
            r'(sql|query)\s*=\s*["\'][^"\']*%[^"\']*["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'python_sql_injection',
                    'cwe_id': 'CWE-89',
                    'severity': 'HIGH',
                    'description': 'SQL injection via string formatting',
                    'line': line_num,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Use parameterized queries with placeholders',
                    'confidence': 'MEDIUM'
                })
        
        return findings
    
    def _check_deserialization(self, code: str) -> List[Dict[str, Any]]:
        """Detect insecure deserialization (CWE-502)"""
        findings = []
        patterns = [
            (r'\bpickle\.loads?\s*\(', 'Pickle deserialization'),
            (r'\byaml\.load\s*\((?!.*Loader\s*=)', 'YAML unsafe load'),
            (r'\bmarshal\.loads\s*\(', 'Marshal deserialization'),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'python_deserialization',
                    'cwe_id': 'CWE-502',
                    'severity': 'HIGH',
                    'description': f'Insecure deserialization: {desc}',
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': 'Use safe alternatives like json.loads or yaml.safe_load',
                    'confidence': 'HIGH'
                })
        
        return findings
    
    def _check_path_traversal(self, code: str) -> List[Dict[str, Any]]:
        """Detect path traversal vulnerabilities (CWE-22)"""
        findings = []
        
        # open() with user input without validation
        pattern = r'\bopen\s*\([^)]*\+[^)]*\)'
        matches = re.finditer(pattern, code)
        
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'rule_id': 'python_path_traversal',
                'cwe_id': 'CWE-22',
                'severity': 'MEDIUM',
                'description': 'Path traversal via file operations',
                'line': line_num,
                'matched_text': match.group(0)[:50],
                'remediation': 'Validate and sanitize file paths',
                'confidence': 'MEDIUM'
            })
        
        return findings
    
    def _check_xxe(self, code: str) -> List[Dict[str, Any]]:
        """Detect XML External Entity injection (CWE-611)"""
        findings = []
        
        # XML parsing without disabling external entities
        patterns = [
            r'\bxml\.etree\.ElementTree\.parse\s*\(',
            r'\bxml\.sax\.parse\s*\(',
            r'\blxml\.etree\.',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # Check if defusedxml is used
                if 'defusedxml' not in code[:match.start()]:
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append({
                        'rule_id': 'python_xxe',
                        'cwe_id': 'CWE-611',
                        'severity': 'MEDIUM',
                        'description': 'XXE vulnerability in XML parsing',
                        'line': line_num,
                        'matched_text': match.group(0),
                        'remediation': 'Use defusedxml library',
                        'confidence': 'MEDIUM'
                    })
        
        return findings
