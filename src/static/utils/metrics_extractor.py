"""
CodeGuardian Static Analysis - Metrics Extractor

This module extracts M1-M15 static code metrics for vulnerability analysis.
"""

import re
from typing import Dict, Any, List, Set
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class MetricsExtractor:
    """
    Extracts static code metrics (M1-M15) from source code.
    These metrics are used as features for ML-based vulnerability detection.
    """
    
    def __init__(self, language: str):
        """
        Initialize metrics extractor for a specific language.
        
        Args:
            language: Programming language identifier
        """
        self.language = language.lower()
        
    def extract_all_metrics(self, code: str) -> Dict[str, Any]:
        """
        Extract all M1-M15 metrics from code.
        
        Args:
            code: Source code string
            
        Returns:
            Dictionary of metric names to values
        """
        return {
            'M1_cyclomatic_complexity': self.m1_cyclomatic_complexity(code),
            'M2_nesting_depth': self.m2_nesting_depth(code),
            'M3_function_call_count': self.m3_function_call_count(code),
            'M4_lines_of_code': self.m4_lines_of_code(code),
            'M5_string_literal_count': self.m5_string_literal_count(code),
            'M6_numeric_literal_count': self.m6_numeric_literal_count(code),
            'M7_api_call_count': self.m7_api_call_count(code),
            'M8_dangerous_function_count': self.m8_dangerous_function_count(code),
            'M9_comment_ratio': self.m9_comment_ratio(code),
            'M10_import_count': self.m10_import_count(code),
            'M11_variable_count': self.m11_variable_count(code),
            'M12_operator_count': self.m12_operator_count(code),
            'M13_control_flow_count': self.m13_control_flow_count(code),
            'M14_exception_handling_count': self.m14_exception_handling_count(code),
            'M15_code_complexity_score': 0.0  # Computed last
        }
    
    def m1_cyclomatic_complexity(self, code: str) -> int:
        """
        M1: Calculate cyclomatic complexity.
        Counts decision points in the code.
        
        Args:
            code: Source code
            
        Returns:
            Cyclomatic complexity value
        """
        # Decision point patterns
        patterns = [
            r'\bif\s*\(',           # if statements
            r'\bfor\s*\(',          # for loops
            r'\bwhile\s*\(',        # while loops
            r'\bcase\s+',           # switch cases
            r'\bcatch\s*\(',        # exception handlers
            r'\&\&',                # logical AND
            r'\|\|',                # logical OR
            r'\?',                  # ternary operator
            r'\belse\s+if\b',       # else if
            r'\belif\b',            # elif (Python)
        ]
        
        complexity = 1  # Base complexity
        for pattern in patterns:
            complexity += len(re.findall(pattern, code, re.IGNORECASE))
        
        return complexity
    
    def m2_nesting_depth(self, code: str) -> int:
        """
        M2: Calculate maximum nesting depth.
        
        Args:
            code: Source code
            
        Returns:
            Maximum nesting depth
        """
        max_depth = 0
        current_depth = 0
        
        # Track braces, brackets, and indentation
        for char in code:
            if char == '{' or char == '[':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}' or char == ']':
                current_depth = max(0, current_depth - 1)
        
        # For Python, count indentation
        if self.language == 'python':
            lines = code.split('\n')
            indent_depth = 0
            for line in lines:
                if line.strip():
                    # Count leading spaces/tabs
                    leading_spaces = len(line) - len(line.lstrip())
                    indent_depth = leading_spaces // 4  # Assume 4-space indentation
                    max_depth = max(max_depth, indent_depth)
        
        return max_depth
    
    def m3_function_call_count(self, code: str) -> int:
        """
        M3: Count function/method calls.
        
        Args:
            code: Source code
            
        Returns:
            Number of function calls
        """
        # Pattern: identifier followed by opening parenthesis
        pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\('
        return len(re.findall(pattern, code))
    
    def m4_lines_of_code(self, code: str) -> int:
        """
        M4: Count non-empty, non-comment lines of code.
        
        Args:
            code: Source code
            
        Returns:
            Lines of code count
        """
        lines = code.split('\n')
        loc = 0
        
        in_multiline_comment = False
        comment_chars = {
            'python': '#',
            'java': '//',
            'cpp': '//',
            'c': '//',
            'javascript': '//',
            'typescript': '//',
            'php': '//',
            'go': '//',
            'ruby': '#',
            'csharp': '//',
        }
        
        comment_char = comment_chars.get(self.language, '#')
        
        for line in lines:
            stripped = line.strip()
            
            # Check for multiline comment start/end
            if '/*' in stripped:
                in_multiline_comment = True
            if '*/' in stripped:
                in_multiline_comment = False
                continue
            
            if in_multiline_comment:
                continue
            
            # Skip empty lines and single-line comments
            if stripped and not stripped.startswith(comment_char):
                loc += 1
        
        return loc
    
    def m5_string_literal_count(self, code: str) -> int:
        """
        M5: Count string literals.
        
        Args:
            code: Source code
            
        Returns:
            Number of string literals
        """
        # Match both single and double quoted strings
        pattern = r'(["\'])(?:(?=(\\?))\2.)*?\1'
        return len(re.findall(pattern, code))
    
    def m6_numeric_literal_count(self, code: str) -> int:
        """
        M6: Count numeric literals.
        
        Args:
            code: Source code
            
        Returns:
            Number of numeric literals
        """
        # Match integers, floats, hex, binary, octal
        patterns = [
            r'\b0x[0-9A-Fa-f]+\b',  # Hex
            r'\b0b[01]+\b',          # Binary
            r'\b0o[0-7]+\b',         # Octal
            r'\b\d+\.\d+\b',         # Float
            r'\b\d+\b',              # Integer
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code))
        
        return count
    
    def m7_api_call_count(self, code: str) -> int:
        """
        M7: Count API/library calls.
        Focuses on common security-sensitive APIs.
        
        Args:
            code: Source code
            
        Returns:
            Number of API calls
        """
        # Language-specific API patterns
        api_patterns = {
            'python': [
                r'\bopen\s*\(',
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'\bos\.\w+\(',
                r'\bsqlite3\.\w+\(',
                r'\brequests\.\w+\(',
            ],
            'java': [
                r'\.execute\s*\(',
                r'\.query\s*\(',
                r'Runtime\.getRuntime\(',
                r'ProcessBuilder\(',
                r'\.getConnection\(',
            ],
            'cpp': [
                r'\bsystem\s*\(',
                r'\bexec\s*\(',
                r'\bfopen\s*\(',
                r'\bstrcpy\s*\(',
                r'\bmemcpy\s*\(',
            ],
            'javascript': [
                r'\beval\s*\(',
                r'\bsetTimeout\s*\(',
                r'\bsetInterval\s*\(',
                r'\.innerHTML\s*=',
                r'\.query\s*\(',
            ],
            'php': [
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'\bsystem\s*\(',
                r'\bshell_exec\s*\(',
                r'\bmysql_query\s*\(',
            ],
        }
        
        patterns = api_patterns.get(self.language, [])
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def m8_dangerous_function_count(self, code: str) -> int:
        """
        M8: Count dangerous/deprecated function calls.
        
        Args:
            code: Source code
            
        Returns:
            Number of dangerous functions found
        """
        dangerous_functions = {
            'python': {'eval', 'exec', 'compile', '__import__', 'pickle', 'marshal'},
            'java': {'Runtime.exec', 'ProcessBuilder', 'Class.forName'},
            'cpp': {'gets', 'strcpy', 'strcat', 'sprintf', 'system', 'exec'},
            'c': {'gets', 'strcpy', 'strcat', 'sprintf', 'system', 'exec'},
            'javascript': {'eval', 'Function', 'setTimeout', 'setInterval'},
            'php': {'eval', 'exec', 'system', 'shell_exec', 'passthru', 'unserialize'},
            'go': {'exec.Command', 'os.Exec', 'unsafe.Pointer'},
        }
        
        funcs = dangerous_functions.get(self.language, set())
        count = 0
        
        for func in funcs:
            pattern = rf'\b{re.escape(func)}\s*\('
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def m9_comment_ratio(self, code: str) -> float:
        """
        M9: Calculate ratio of comment lines to total lines.
        
        Args:
            code: Source code
            
        Returns:
            Comment ratio (0.0 to 1.0)
        """
        lines = code.split('\n')
        total_lines = len(lines)
        
        if total_lines == 0:
            return 0.0
        
        comment_lines = 0
        comment_chars = {
            'python': '#',
            'java': '//',
            'cpp': '//',
            'c': '//',
            'javascript': '//',
            'typescript': '//',
            'php': '//',
            'go': '//',
            'ruby': '#',
            'csharp': '//',
        }
        
        comment_char = comment_chars.get(self.language, '#')
        in_multiline = False
        
        for line in lines:
            stripped = line.strip()
            
            if '/*' in stripped or '"""' in stripped:
                in_multiline = True
            
            if in_multiline or stripped.startswith(comment_char) or stripped.startswith('*'):
                comment_lines += 1
            
            if '*/' in stripped or '"""' in stripped:
                in_multiline = False
        
        return round(comment_lines / total_lines, 3)
    
    def m10_import_count(self, code: str) -> int:
        """
        M10: Count import/include statements.
        
        Args:
            code: Source code
            
        Returns:
            Number of imports
        """
        import_patterns = {
            'python': [r'^\s*import\s+', r'^\s*from\s+\w+\s+import\s+'],
            'java': [r'^\s*import\s+'],
            'cpp': [r'^\s*#include\s+'],
            'c': [r'^\s*#include\s+'],
            'javascript': [r'^\s*import\s+', r'\brequire\s*\('],
            'typescript': [r'^\s*import\s+', r'\brequire\s*\('],
            'php': [r'\buse\s+', r'\brequire', r'\binclude'],
            'go': [r'^\s*import\s+'],
        }
        
        patterns = import_patterns.get(self.language, [])
        count = 0
        
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.MULTILINE | re.IGNORECASE))
        
        return count
    
    def m11_variable_count(self, code: str) -> int:
        """
        M11: Estimate variable declaration count.
        
        Args:
            code: Source code
            
        Returns:
            Estimated number of variables
        """
        var_patterns = {
            'python': [r'^\s*\w+\s*='],
            'java': [r'\b(int|long|double|float|String|boolean|char|byte|short)\s+\w+'],
            'cpp': [r'\b(int|long|double|float|char|bool|auto|void\*)\s+\w+'],
            'c': [r'\b(int|long|double|float|char|void\*)\s+\w+'],
            'javascript': [r'\b(var|let|const)\s+\w+'],
            'typescript': [r'\b(var|let|const)\s+\w+'],
            'php': [r'\$\w+\s*='],
            'go': [r'\b\w+\s*:=', r'\bvar\s+\w+'],
        }
        
        patterns = var_patterns.get(self.language, [r'\b\w+\s*='])
        count = 0
        
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.MULTILINE | re.IGNORECASE))
        
        return count
    
    def m12_operator_count(self, code: str) -> int:
        """
        M12: Count operators (arithmetic, logical, comparison).
        
        Args:
            code: Source code
            
        Returns:
            Number of operators
        """
        operators = [
            r'\+', r'-', r'\*', r'/', r'%',  # Arithmetic
            r'==', r'!=', r'<', r'>', r'<=', r'>=',  # Comparison
            r'\&\&', r'\|\|', r'!',  # Logical
            r'\&', r'\|', r'\^', r'~', r'<<', r'>>',  # Bitwise
        ]
        
        count = 0
        for op in operators:
            count += len(re.findall(op, code))
        
        return count
    
    def m13_control_flow_count(self, code: str) -> int:
        """
        M13: Count control flow statements.
        
        Args:
            code: Source code
            
        Returns:
            Number of control flow statements
        """
        patterns = [
            r'\bif\b',
            r'\belse\b',
            r'\belif\b',
            r'\bfor\b',
            r'\bwhile\b',
            r'\bswitch\b',
            r'\bcase\b',
            r'\bbreak\b',
            r'\bcontinue\b',
            r'\breturn\b',
            r'\bgoto\b',
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def m14_exception_handling_count(self, code: str) -> int:
        """
        M14: Count exception handling constructs.
        
        Args:
            code: Source code
            
        Returns:
            Number of exception handling statements
        """
        patterns = [
            r'\btry\b',
            r'\bcatch\b',
            r'\bfinally\b',
            r'\bexcept\b',
            r'\bthrow\b',
            r'\braise\b',
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def m15_code_complexity_score(self, metrics: Dict[str, Any]) -> float:
        """
        M15: Compute overall code complexity score from other metrics.
        
        Args:
            metrics: Dictionary of M1-M14 metrics
            
        Returns:
            Normalized complexity score (0.0 to 1.0)
        """
        # Weighted combination of metrics
        weights = {
            'M1_cyclomatic_complexity': 0.20,
            'M2_nesting_depth': 0.15,
            'M3_function_call_count': 0.10,
            'M4_lines_of_code': 0.10,
            'M7_api_call_count': 0.10,
            'M8_dangerous_function_count': 0.15,
            'M13_control_flow_count': 0.10,
            'M14_exception_handling_count': 0.10,
        }
        
        # Normalize each metric to 0-1 range
        normalized = {}
        thresholds = {
            'M1_cyclomatic_complexity': 20,
            'M2_nesting_depth': 6,
            'M3_function_call_count': 30,
            'M4_lines_of_code': 200,
            'M7_api_call_count': 10,
            'M8_dangerous_function_count': 5,
            'M13_control_flow_count': 20,
            'M14_exception_handling_count': 10,
        }
        
        for metric, weight in weights.items():
            value = metrics.get(metric, 0)
            threshold = thresholds.get(metric, 1)
            normalized[metric] = min(value / threshold, 1.0) * weight
        
        complexity_score = sum(normalized.values())
        return round(complexity_score, 3)
    
    def compute_all_metrics_with_score(self, code: str) -> Dict[str, Any]:
        """
        Extract all metrics including the complexity score.
        
        Args:
            code: Source code
            
        Returns:
            Complete metrics dictionary
        """
        metrics = self.extract_all_metrics(code)
        metrics['M15_code_complexity_score'] = self.m15_code_complexity_score(metrics)
        return metrics
