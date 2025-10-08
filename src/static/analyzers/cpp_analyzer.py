"""
C/C++ Static Code Analyzer
Specialized analyzer for C and C++ vulnerability detection
"""
from typing import Dict, List, Any
from .base_analyzer import BaseAnalyzer
from ..features.static_feature_extractor import StaticFeatureExtractor
import re


class CppAnalyzer(BaseAnalyzer):
    """Analyzer for C and C++ code"""
    
    def __init__(self, language: str, rule_engine=None):
        super().__init__(language, rule_engine)
        self.feature_extractor = StaticFeatureExtractor()
        
        # C/C++ specific dangerous functions
        self.dangerous_functions = {
            'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
            'strncpy', 'strncat', 'memcpy', 'memmove',
            'system', 'popen', 'exec', 'execl', 'execlp', 'execle',
            'malloc', 'realloc', 'alloca'
        }
        
        # Security-relevant APIs
        self.security_apis = [
            r'\b(strcpy|strcat|sprintf|gets|scanf)\s*\(',
            r'\b(system|popen|exec)\s*\(',
            r'\b(malloc|realloc|free|alloca)\s*\(',
            r'\b(fopen|fread|fwrite|fclose)\s*\(',
            r'\bsocket\s*\(',
            r'\baccept\s*\(',
        ]
    
    def analyze(self, code: str, record_id: str = None) -> Dict[str, Any]:
        """Perform complete C/C++ static analysis"""
        # Extract metrics
        metrics = self.extract_metrics(code)
        
        # Detect vulnerabilities
        vulnerabilities = self.detect_vulnerabilities(code)
        
        # Generate static flags
        static_flags = self.generate_static_flags(metrics, vulnerabilities)
        
        # Calculate severity
        severity_scores = self.calculate_severity_score(vulnerabilities)
        
        # Map to CWEs
        detected_cwes = self.map_vulnerabilities_to_cwes(vulnerabilities)
        
        # Compute overall confidence
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
        """Extract all static metrics for C/C++ code"""
        metrics = self.feature_extractor.extract_all_features(code, self.language)
        
        # Add C/C++-specific metrics
        metrics['pointer_operations'] = self.count_pointer_operations(code)
        metrics['memory_operations'] = self.count_memory_operations(code)
        metrics['buffer_operations'] = self.count_buffer_operations(code)
        
        return metrics
    
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """Detect C/C++ specific vulnerabilities"""
        vulnerabilities = []
        
        # Use rule engine if available
        if self.rule_engine and self.rules:
            metrics = self.extract_metrics(code)
            vulnerabilities.extend(
                self.rule_engine.execute_all_rules(self.rules, code, metrics)
            )
        
        # Additional C/C++ specific checks
        vulnerabilities.extend(self._check_buffer_overflow(code))
        vulnerabilities.extend(self._check_format_string(code))
        vulnerabilities.extend(self._check_integer_overflow(code))
        vulnerabilities.extend(self._check_use_after_free(code))
        vulnerabilities.extend(self._check_null_pointer(code))
        
        return vulnerabilities
    
    def _check_buffer_overflow(self, code: str) -> List[Dict[str, Any]]:
        """Detect potential buffer overflow vulnerabilities (CWE-120)"""
        findings = []
        
        # Unsafe string functions
        unsafe_patterns = [
            (r'\bstrcpy\s*\(', 'strcpy without bounds checking'),
            (r'\bstrcat\s*\(', 'strcat without bounds checking'),
            (r'\bsprintf\s*\(', 'sprintf without bounds checking'),
            (r'\bgets\s*\(', 'gets() is inherently unsafe'),
            (r'\bscanf\s*\([^,]*%s', 'scanf with %s without width specifier'),
        ]
        
        for pattern, desc in unsafe_patterns:
            matches = re.finditer(pattern, code, re.MULTILINE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'cpp_buffer_overflow',
                    'cwe_id': 'CWE-120',
                    'severity': 'HIGH',
                    'description': f'Buffer overflow risk: {desc}',
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': 'Use safe alternatives like strncpy, strncat, snprintf',
                    'confidence': 'HIGH'
                })
        
        return findings
    
    def _check_format_string(self, code: str) -> List[Dict[str, Any]]:
        """Detect format string vulnerabilities (CWE-134)"""
        findings = []
        
        # Format functions with non-literal format strings
        pattern = r'\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*[a-zA-Z_]'
        
        matches = re.finditer(pattern, code, re.MULTILINE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'rule_id': 'cpp_format_string',
                'cwe_id': 'CWE-134',
                'severity': 'HIGH',
                'description': 'Potential format string vulnerability',
                'line': line_num,
                'matched_text': match.group(0),
                'remediation': 'Use string literal as format string',
                'confidence': 'MEDIUM'
            })
        
        return findings
    
    def _check_integer_overflow(self, code: str) -> List[Dict[str, Any]]:
        """Detect potential integer overflow (CWE-190)"""
        findings = []
        
        # Arithmetic without overflow checks
        patterns = [
            r'\b\w+\s*\+\s*\w+\s*\)',
            r'\b\w+\s*\*\s*\w+\s*\)',
        ]
        
        # Check for malloc/alloca with arithmetic
        malloc_arith = r'\b(malloc|alloca|realloc)\s*\([^)]*[+*][^)]*\)'
        matches = re.finditer(malloc_arith, code)
        
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'rule_id': 'cpp_integer_overflow',
                'cwe_id': 'CWE-190',
                'severity': 'MEDIUM',
                'description': 'Potential integer overflow in memory allocation',
                'line': line_num,
                'matched_text': match.group(0)[:50],
                'remediation': 'Validate arithmetic operations before allocation',
                'confidence': 'MEDIUM'
            })
        
        return findings
    
    def _check_use_after_free(self, code: str) -> List[Dict[str, Any]]:
        """Detect potential use-after-free (CWE-416)"""
        findings = []
        
        # Simple heuristic: free() followed by potential use
        lines = code.split('\n')
        freed_vars = set()
        
        for i, line in enumerate(lines):
            # Check for free()
            free_match = re.search(r'\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                freed_vars.add(var_name)
            
            # Check for use of freed variables
            for var in freed_vars:
                if var in line and 'free' not in line:
                    findings.append({
                        'rule_id': 'cpp_use_after_free',
                        'cwe_id': 'CWE-416',
                        'severity': 'HIGH',
                        'description': f'Potential use of freed pointer: {var}',
                        'line': i + 1,
                        'matched_text': line.strip()[:50],
                        'remediation': 'Set pointer to NULL after free',
                        'confidence': 'LOW'
                    })
                    break
        
        return findings
    
    def _check_null_pointer(self, code: str) -> List[Dict[str, Any]]:
        """Detect null pointer dereference (CWE-476)"""
        findings = []
        
        # Pointer dereference without null check
        pattern = r'(\w+)\s*=\s*(malloc|realloc|calloc)\s*\([^)]+\)\s*;[^}]*?\*\1'
        
        matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
        for match in matches:
            # Check if there's a null check between allocation and use
            snippet = match.group(0)
            if 'if' not in snippet and 'NULL' not in snippet:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    'rule_id': 'cpp_null_pointer',
                    'cwe_id': 'CWE-476',
                    'severity': 'MEDIUM',
                    'description': 'Pointer dereference without null check',
                    'line': line_num,
                    'matched_text': match.group(0)[:50],
                    'remediation': 'Check for NULL before dereferencing',
                    'confidence': 'LOW'
                })
        
        return findings
    
    def count_pointer_operations(self, code: str) -> int:
        """Count pointer operations (dereference, address-of)"""
        deref = len(re.findall(r'\*\s*\w+', code))
        addr_of = len(re.findall(r'\&\s*\w+', code))
        return deref + addr_of
    
    def count_memory_operations(self, code: str) -> int:
        """Count memory management operations"""
        malloc_count = len(re.findall(r'\b(malloc|calloc|realloc|free)\s*\(', code))
        new_delete = len(re.findall(r'\b(new|delete)\s+', code))
        return malloc_count + new_delete
    
    def count_buffer_operations(self, code: str) -> int:
        """Count buffer manipulation operations"""
        patterns = [
            r'\b(strcpy|strcat|strncpy|strncat|memcpy|memmove|memset)\s*\('
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code))
        return count
