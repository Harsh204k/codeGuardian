"""
Base Abstract Analyzer for Static Code Analysis
Provides common interface for all language-specific analyzers
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
import re
from pathlib import Path


class BaseAnalyzer(ABC):
    """
    Abstract base class for language-specific static code analyzers.
    All language analyzers must extend this class and implement required methods.
    """

    def __init__(self, language: str, rule_engine=None):
        """
        Initialize base analyzer
        
        Args:
            language: Programming language identifier (e.g., 'python', 'java')
            rule_engine: RuleEngine instance for loading and applying rules
        """
        self.language = language.lower()
        self.rule_engine = rule_engine
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    @abstractmethod
    def analyze(self, code: str, record_id: str = None) -> Dict[str, Any]:
        """
        Perform complete static analysis on code snippet
        
        Args:
            code: Source code string to analyze
            record_id: Unique identifier for the code record
            
        Returns:
            Dictionary containing analysis results:
            {
                'id': record_id,
                'language': language,
                'static_metrics': {...},
                'detected_cwes': [...],
                'static_flags': {...},
                'vulnerability_count': int,
                'severity_scores': {...}
            }
        """
        pass

    @abstractmethod
    def extract_metrics(self, code: str) -> Dict[str, Any]:
        """
        Extract static code metrics (M1-M15)
        
        Args:
            code: Source code string
            
        Returns:
            Dictionary of metric name -> value pairs
            Example: {'M1_cyclomatic_complexity': 5, 'M2_nesting_depth': 3, ...}
        """
        pass

    def load_rules(self) -> None:
        """
        Load language-specific and shared vulnerability detection rules
        Uses rule_engine if available, otherwise loads default rules
        """
        if self.rule_engine:
            self.rules = self.rule_engine.load_rules_for_language(self.language)
        else:
            self.rules = []

    @abstractmethod
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using loaded rules
        
        Args:
            code: Source code string
            
        Returns:
            List of detected vulnerability dictionaries:
            [{
                'cwe_id': 'CWE-89',
                'rule_id': 'sql_injection_basic',
                'severity': 'HIGH',
                'line': 42,
                'description': '...',
                'remediation': '...'
            }, ...]
        """
        pass

    def compute_cyclomatic_complexity(self, code: str) -> int:
        """
        Calculate cyclomatic complexity (M1 metric)
        Base implementation counts decision points
        
        Args:
            code: Source code string
            
        Returns:
            Cyclomatic complexity value
        """
        # Count decision points: if, for, while, case, catch, &&, ||, ?
        patterns = [
            r'\bif\s*\(',
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\&\&',
            r'\|\|',
            r'\?'
        ]
        
        complexity = 1  # Base complexity
        for pattern in patterns:
            complexity += len(re.findall(pattern, code, re.IGNORECASE))
        
        return complexity

    def compute_nesting_depth(self, code: str) -> int:
        """
        Calculate maximum nesting depth (M2 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Maximum nesting depth
        """
        max_depth = 0
        current_depth = 0
        
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth

    def count_function_calls(self, code: str) -> int:
        """
        Count function/method calls (M3 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Number of function calls
        """
        # Basic pattern: identifier followed by (
        pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\('
        return len(re.findall(pattern, code))

    def count_lines_of_code(self, code: str) -> int:
        """
        Count non-empty, non-comment lines (M4 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Lines of code count
        """
        lines = code.split('\n')
        loc = 0
        
        for line in lines:
            stripped = line.strip()
            # Skip empty lines and single-line comments
            if stripped and not stripped.startswith('//') and not stripped.startswith('#'):
                loc += 1
        
        return loc

    def count_string_literals(self, code: str) -> int:
        """
        Count string literals in code (M5 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Number of string literals
        """
        # Match both single and double quoted strings
        pattern = r'(["\'])(?:(?=(\\?))\2.)*?\1'
        return len(re.findall(pattern, code))

    def count_numeric_literals(self, code: str) -> int:
        """
        Count numeric literals in code (M6 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Number of numeric literals
        """
        # Match integers, floats, hex, binary
        pattern = r'\b(0x[0-9A-Fa-f]+|0b[01]+|\d+\.?\d*)\b'
        return len(re.findall(pattern, code))

    def count_api_calls(self, code: str, api_patterns: List[str]) -> int:
        """
        Count API calls matching specific patterns (M7 metric)
        
        Args:
            code: Source code string
            api_patterns: List of API patterns to search for
            
        Returns:
            Number of API calls found
        """
        count = 0
        for pattern in api_patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        return count

    def detect_dangerous_functions(self, code: str, dangerous_funcs: Set[str]) -> List[str]:
        """
        Detect usage of dangerous functions (M8 metric)
        
        Args:
            code: Source code string
            dangerous_funcs: Set of dangerous function names
            
        Returns:
            List of detected dangerous functions
        """
        detected = []
        for func in dangerous_funcs:
            pattern = rf'\b{re.escape(func)}\s*\('
            if re.search(pattern, code):
                detected.append(func)
        return detected

    def compute_comment_ratio(self, code: str) -> float:
        """
        Calculate ratio of comment lines to total lines (M9 metric)
        
        Args:
            code: Source code string
            
        Returns:
            Comment ratio (0.0 to 1.0)
        """
        lines = code.split('\n')
        total_lines = len(lines)
        
        if total_lines == 0:
            return 0.0
        
        comment_lines = 0
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or \
               stripped.startswith('/*') or stripped.startswith('*'):
                comment_lines += 1
        
        return comment_lines / total_lines

    def extract_imported_modules(self, code: str) -> List[str]:
        """
        Extract imported modules/libraries (M10 metric)
        
        Args:
            code: Source code string
            
        Returns:
            List of imported module names
        """
        imports = []
        
        # Python: import X, from X import Y
        imports.extend(re.findall(r'^\s*import\s+([\w\.]+)', code, re.MULTILINE))
        imports.extend(re.findall(r'^\s*from\s+([\w\.]+)\s+import', code, re.MULTILINE))
        
        # Java: import X;
        imports.extend(re.findall(r'^\s*import\s+([\w\.]+);', code, re.MULTILINE))
        
        # JavaScript: require('X'), import X from 'Y'
        imports.extend(re.findall(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', code))
        imports.extend(re.findall(r'import\s+.*?from\s+["\']([^"\']+)["\']', code))
        
        return list(set(imports))  # Remove duplicates

    def calculate_severity_score(self, detected_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate aggregate severity scores
        
        Args:
            detected_vulnerabilities: List of detected vulnerability dictionaries
            
        Returns:
            Dictionary with severity counts and weighted score
        """
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        total_score = 0
        
        for vuln in detected_vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
                total_score += severity_weights[severity]
        
        return {
            'counts': severity_counts,
            'total_score': total_score,
            'max_severity': self._get_max_severity(severity_counts)
        }

    def _get_max_severity(self, severity_counts: Dict[str, int]) -> str:
        """Get the highest severity level present"""
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity_counts[severity] > 0:
                return severity
        return 'NONE'

    def map_vulnerabilities_to_cwes(self, detected_vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Extract unique CWE IDs from detected vulnerabilities
        
        Args:
            detected_vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of unique CWE IDs
        """
        cwes = set()
        for vuln in detected_vulnerabilities:
            cwe_id = vuln.get('cwe_id')
            if cwe_id:
                cwes.add(cwe_id)
        return sorted(list(cwes))

    def generate_static_flags(self, metrics: Dict[str, Any], 
                            vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate binary/numeric flags for ML model input
        
        Args:
            metrics: Static metrics dictionary
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Dictionary of flags for ML fusion model
        """
        severity_score = self.calculate_severity_score(vulnerabilities)
        
        return {
            'has_vulnerabilities': len(vulnerabilities) > 0,
            'vulnerability_count': len(vulnerabilities),
            'critical_count': severity_score['counts']['CRITICAL'],
            'high_count': severity_score['counts']['HIGH'],
            'medium_count': severity_score['counts']['MEDIUM'],
            'low_count': severity_score['counts']['LOW'],
            'severity_score': severity_score['total_score'],
            'max_severity': severity_score['max_severity'],
            'high_complexity': metrics.get('M1_cyclomatic_complexity', 0) > 10,
            'deep_nesting': metrics.get('M2_nesting_depth', 0) > 4,
            'has_dangerous_apis': len(metrics.get('M8_dangerous_functions', [])) > 0,
            'low_comment_ratio': metrics.get('M9_comment_ratio', 0) < 0.1
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(language='{self.language}', rules={len(self.rules)})>"
