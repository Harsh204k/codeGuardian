"""
Java Static Code Analyzer
Specialized analyzer for Java vulnerability detection
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class JavaAnalyzer(BaseAnalyzer):
    """Analyzer for Java code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        
        self.dangerous_functions = {
            'Runtime.exec', 'ProcessBuilder', 'deserialize',
            'readObject', 'ObjectInputStream',
            'ScriptEngine.eval', 'Class.forName'
        }
        
        self.security_apis = [
            r'\bRuntime\.getRuntime\(\)\.exec\s*\(',
            r'\bProcessBuilder\s*\(',
            r'\breadObject\s*\(',
            r'\bObjectInputStream\s*\(',
            r'\.createStatement\s*\(',
            r'\.executeQuery\s*\(',
        ]
    
    def analyze(self, code: str, record_id: str = None) -> Dict[str, Any]:
        """Perform complete Java static analysis"""
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
        """Extract all static metrics for Java code"""
        return self.feature_extractor.extract_all_features(code, self.language)
    
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """Detect Java specific vulnerabilities"""
        vulnerabilities = []
        
        if self.rule_engine and self.rules:
            metrics = self.extract_metrics(code)
            vulnerabilities.extend(
                self.rule_engine.execute_all_rules(self.rules, code, metrics)
            )
        
        vulnerabilities.extend(self._check_sql_injection(code))
        vulnerabilities.extend(self._check_command_injection(code))
        vulnerabilities.extend(self._check_deserialization(code))
        vulnerabilities.extend(self._check_xxe(code))
        vulnerabilities.extend(self._check_path_traversal(code))
        
        return vulnerabilities
    
    def _check_sql_injection(self, code: str) -> List[Dict[str, Any]]:
        """Detect SQL injection vulnerabilities (CWE-89)"""
        findings = []
        
        # String concatenation in SQL
        patterns = [
            r'(executeQuery|executeUpdate|execute)\s*\([^)]*\+[^)]*\)',
            r'(createStatement|prepareStatement)\s*\([^)]*\+[^)]*\)',
            r'(query|sql)\s*=\s*["\'][^"\']*\+',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'java_sql_injection',
                    'cwe_id': 'CWE-89',
                    'severity': 'HIGH',
                    'description': 'SQL injection via string concatenation',
                    'line': line_num,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Use PreparedStatement with parameterized queries',
                    'confidence': 'HIGH'
                })
        
        return findings
    
    def _check_command_injection(self, code: str) -> List[Dict[str, Any]]:
        """Detect command injection (CWE-78)"""
        findings = []
        
        patterns = [
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Runtime.exec() usage'),
            (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder with concatenation'),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'java_command_injection',
                    'cwe_id': 'CWE-78',
                    'severity': 'HIGH',
                    'description': f'Command injection risk: {desc}',
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': 'Validate and sanitize command inputs',
                    'confidence': 'MEDIUM'
                })
        
        return findings
    
    def _check_deserialization(self, code: str) -> List[Dict[str, Any]]:
        """Detect insecure deserialization (CWE-502)"""
        findings = []
        
        patterns = [
            (r'\breadObject\s*\(', 'ObjectInputStream.readObject()'),
            (r'\bObjectInputStream\s*\(', 'ObjectInputStream usage'),
            (r'\.deserialize\s*\(', 'Deserialization'),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'java_deserialization',
                    'cwe_id': 'CWE-502',
                    'severity': 'HIGH',
                    'description': f'Insecure deserialization: {desc}',
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': 'Implement input validation and use safe deserialization',
                    'confidence': 'HIGH'
                })
        
        return findings
    
    def _check_xxe(self, code: str) -> List[Dict[str, Any]]:
        """Detect XML External Entity injection (CWE-611)"""
        findings = []
        
        # XML parsing without secure configuration
        patterns = [
            r'DocumentBuilderFactory\.newInstance\s*\(',
            r'SAXParserFactory\.newInstance\s*\(',
            r'XMLInputFactory\.newInstance\s*\(',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # Check if secure features are set
                snippet = code[match.start():match.start()+500]
                if 'setFeature' not in snippet or 'disallow-doctype-decl' not in snippet:
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append({
                        'rule_id': 'java_xxe',
                        'cwe_id': 'CWE-611',
                        'severity': 'MEDIUM',
                        'description': 'XXE vulnerability in XML parsing',
                        'line': line_num,
                        'matched_text': match.group(0),
                        'remediation': 'Disable external entity processing',
                        'confidence': 'MEDIUM'
                    })
        
        return findings
    
    def _check_path_traversal(self, code: str) -> List[Dict[str, Any]]:
        """Detect path traversal vulnerabilities (CWE-22)"""
        findings = []
        
        # File operations with user input
        pattern = r'new\s+File\s*\([^)]*\+[^)]*\)'
        matches = re.finditer(pattern, code)
        
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'rule_id': 'java_path_traversal',
                'cwe_id': 'CWE-22',
                'severity': 'MEDIUM',
                'description': 'Path traversal via file operations',
                'line': line_num,
                'matched_text': match.group(0)[:50],
                'remediation': 'Validate and canonicalize file paths',
                'confidence': 'MEDIUM'
            })
        
        return findings
