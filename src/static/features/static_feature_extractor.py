"""
Static Feature Extractor
Computes M1-M15 metrics for vulnerability prediction
"""
import re
from typing import Dict, Any, List, Set
import logging


logger = logging.getLogger(__name__)


class StaticFeatureExtractor:
    """
    Extracts comprehensive static code metrics (M1-M15) for vulnerability analysis.
    These features are used as input to the XGBoost fusion model.
    """
    
    def __init__(self):
        """Initialize feature extractor"""
        self.feature_names = [
            'M1_cyclomatic_complexity',
            'M2_nesting_depth',
            'M3_function_call_count',
            'M4_lines_of_code',
            'M5_string_literal_count',
            'M6_numeric_literal_count',
            'M7_api_call_count',
            'M8_dangerous_function_count',
            'M9_comment_ratio',
            'M10_import_count',
            'M11_variable_count',
            'M12_conditional_count',
            'M13_loop_count',
            'M14_exception_handling_count',
            'M15_code_complexity_score'
        ]
    
    def extract_all_features(self, code: str, language: str = None) -> Dict[str, Any]:
        """
        Extract all M1-M15 features from code
        
        Args:
            code: Source code string
            language: Programming language (for language-specific features)
            
        Returns:
            Dictionary of feature name -> value pairs
        """
        features = {
            'M1_cyclomatic_complexity': self.compute_cyclomatic_complexity(code),
            'M2_nesting_depth': self.compute_nesting_depth(code),
            'M3_function_call_count': self.count_function_calls(code),
            'M4_lines_of_code': self.count_lines_of_code(code),
            'M5_string_literal_count': self.count_string_literals(code),
            'M6_numeric_literal_count': self.count_numeric_literals(code),
            'M7_api_call_count': self.count_api_calls(code, language),
            'M8_dangerous_function_count': len(self.detect_dangerous_functions(code, language)),
            'M8_dangerous_functions': self.detect_dangerous_functions(code, language),
            'M9_comment_ratio': self.compute_comment_ratio(code),
            'M10_import_count': len(self.extract_imports(code, language)),
            'M10_imports': self.extract_imports(code, language),
            'M11_variable_count': self.count_variables(code),
            'M12_conditional_count': self.count_conditionals(code),
            'M13_loop_count': self.count_loops(code),
            'M14_exception_handling_count': self.count_exception_handling(code, language),
            'M15_code_complexity_score': 0.0  # Computed below
        }
        
        # M15: Aggregate complexity score
        features['M15_code_complexity_score'] = self.compute_complexity_score(features)
        
        return features
    
    def compute_cyclomatic_complexity(self, code: str) -> int:
        """
        M1: Cyclomatic complexity - measures code complexity via decision points
        Formula: CC = E - N + 2P (simplified: count decision points + 1)
        """
        patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\belif\s*\(',
            r'\bfor\s*\(',
            r'\bforeach\s*\(',
            r'\bwhile\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\&\&',
            r'\|\|',
            r'\?',
            r'\bswitch\s*\('
        ]
        
        complexity = 1  # Base complexity
        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            complexity += len(matches)
        
        return complexity
    
    def compute_nesting_depth(self, code: str) -> int:
        """
        M2: Maximum nesting depth - measures code structure complexity
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
        M3: Number of function/method calls
        """
        # Pattern: identifier followed by (
        pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\('
        return len(re.findall(pattern, code))
    
    def count_lines_of_code(self, code: str) -> int:
        """
        M4: Lines of code (non-empty, non-comment)
        """
        lines = code.split('\n')
        loc = 0
        
        in_block_comment = False
        
        for line in lines:
            stripped = line.strip()
            
            # Handle block comments
            if '/*' in stripped:
                in_block_comment = True
            if '*/' in stripped:
                in_block_comment = False
                continue
            
            if in_block_comment:
                continue
            
            # Skip empty lines and single-line comments
            if stripped and not stripped.startswith('//') and \
               not stripped.startswith('#') and not stripped.startswith('*'):
                loc += 1
        
        return loc
    
    def count_string_literals(self, code: str) -> int:
        """
        M5: Number of string literals (potential injection points)
        """
        # Match both single and double quoted strings
        single_quote = r"'(?:[^'\\]|\\.)*'"
        double_quote = r'"(?:[^"\\]|\\.)*"'
        template_literal = r'`(?:[^`\\]|\\.)*`'
        
        count = 0
        count += len(re.findall(single_quote, code))
        count += len(re.findall(double_quote, code))
        count += len(re.findall(template_literal, code))
        
        return count
    
    def count_numeric_literals(self, code: str) -> int:
        """
        M6: Number of numeric literals
        """
        # Match integers, floats, hex, binary, octal
        pattern = r'\b(0x[0-9A-Fa-f]+|0b[01]+|0o[0-7]+|\d+\.?\d*[eE]?[+-]?\d*)\b'
        return len(re.findall(pattern, code))
    
    def count_api_calls(self, code: str, language: str = None) -> int:
        """
        M7: Count of security-relevant API calls
        """
        security_apis = [
            # Network/HTTP
            r'\b(http|https|fetch|request|axios|curl|urllib|requests)\.',
            r'\bSocket\(',
            # Database
            r'\b(execute|query|exec|prepare|Statement)\s*\(',
            # File I/O
            r'\b(open|read|write|fopen|fread|fwrite|File)\s*\(',
            # Process execution
            r'\b(exec|system|popen|subprocess|Runtime|Process)\.',
            # Crypto
            r'\b(encrypt|decrypt|hash|md5|sha|crypto|cipher)\.',
        ]
        
        count = 0
        for pattern in security_apis:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def detect_dangerous_functions(self, code: str, language: str = None) -> List[str]:
        """
        M8: Detect usage of dangerous/deprecated functions
        """
        dangerous_funcs = {
            # C/C++
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
            # Python
            'eval', 'exec', 'compile', '__import__', 'pickle.loads',
            # JavaScript
            'eval', 'Function',
            # PHP
            'eval', 'assert', 'system', 'exec', 'passthru', 'shell_exec',
            # Java
            'Runtime.exec', 'ProcessBuilder',
            # SQL
            'execute', 'executeQuery', 'rawQuery',
        }
        
        detected = []
        for func in dangerous_funcs:
            pattern = rf'\b{re.escape(func)}\s*\('
            if re.search(pattern, code):
                detected.append(func)
        
        return detected
    
    def compute_comment_ratio(self, code: str) -> float:
        """
        M9: Ratio of comment lines to total lines (code documentation quality)
        """
        lines = code.split('\n')
        total_lines = len(lines)
        
        if total_lines == 0:
            return 0.0
        
        comment_lines = 0
        in_block_comment = False
        
        for line in lines:
            stripped = line.strip()
            
            # Block comments
            if '/*' in stripped:
                in_block_comment = True
            if in_block_comment:
                comment_lines += 1
            if '*/' in stripped:
                in_block_comment = False
                continue
            
            # Single line comments
            if stripped.startswith('//') or stripped.startswith('#') or \
               stripped.startswith('*'):
                comment_lines += 1
        
        return comment_lines / total_lines if total_lines > 0 else 0.0
    
    def extract_imports(self, code: str, language: str = None) -> List[str]:
        """
        M10: Extract imported modules/libraries
        """
        imports = []
        
        # Python
        imports.extend(re.findall(r'^\s*import\s+([\w\.]+)', code, re.MULTILINE))
        imports.extend(re.findall(r'^\s*from\s+([\w\.]+)\s+import', code, re.MULTILINE))
        
        # Java
        imports.extend(re.findall(r'^\s*import\s+([\w\.]+);', code, re.MULTILINE))
        
        # JavaScript/TypeScript
        imports.extend(re.findall(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', code))
        imports.extend(re.findall(r'import\s+.*?from\s+["\']([^"\']+)["\']', code))
        
        # C/C++
        imports.extend(re.findall(r'#include\s*[<"]([^>"]+)[>"]', code))
        
        # PHP
        imports.extend(re.findall(r'(?:require|include)(?:_once)?\s*\(?["\']([^"\']+)["\']', code))
        
        # Go
        imports.extend(re.findall(r'import\s+["\']([^"\']+)["\']', code))
        
        # Ruby
        imports.extend(re.findall(r'require\s+["\']([^"\']+)["\']', code))
        
        return list(set(imports))  # Remove duplicates
    
    def count_variables(self, code: str) -> int:
        """
        M11: Count variable declarations
        """
        patterns = [
            r'\b(var|let|const)\s+\w+',  # JavaScript
            r'\b(int|long|float|double|char|string|bool|auto)\s+\w+',  # C/C++/Java
            r'\b\w+\s*=\s*',  # Generic assignment
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code))
        
        return count
    
    def count_conditionals(self, code: str) -> int:
        """
        M12: Count conditional statements
        """
        patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\belif\s*\(',
            r'\belse\s*{',
            r'\bswitch\s*\(',
            r'\bcase\s+',
            r'\?.*:',  # Ternary operator
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def count_loops(self, code: str) -> int:
        """
        M13: Count loop constructs
        """
        patterns = [
            r'\bfor\s*\(',
            r'\bforeach\s*\(',
            r'\bwhile\s*\(',
            r'\bdo\s*{',
            r'\.map\s*\(',
            r'\.forEach\s*\(',
            r'\.filter\s*\(',
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def count_exception_handling(self, code: str, language: str = None) -> int:
        """
        M14: Count exception handling blocks
        """
        patterns = [
            r'\btry\s*{',
            r'\bcatch\s*\(',
            r'\bfinally\s*{',
            r'\bexcept\s*:',
            r'\bexcept\s+\w+',
            r'\braise\s+',
            r'\bthrow\s+',
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
        
        return count
    
    def compute_complexity_score(self, features: Dict[str, Any]) -> float:
        """
        M15: Aggregate code complexity score
        Weighted combination of multiple metrics
        """
        weights = {
            'M1_cyclomatic_complexity': 0.25,
            'M2_nesting_depth': 0.20,
            'M3_function_call_count': 0.10,
            'M4_lines_of_code': 0.15,
            'M12_conditional_count': 0.15,
            'M13_loop_count': 0.15
        }
        
        # Normalize and weight
        score = 0.0
        
        # Cyclomatic complexity (normalize to 0-10 scale)
        cc = min(features.get('M1_cyclomatic_complexity', 0) / 10.0, 1.0)
        score += cc * weights['M1_cyclomatic_complexity']
        
        # Nesting depth (normalize to 0-10 scale)
        nd = min(features.get('M2_nesting_depth', 0) / 10.0, 1.0)
        score += nd * weights['M2_nesting_depth']
        
        # Function calls (normalize to 0-100 scale)
        fc = min(features.get('M3_function_call_count', 0) / 100.0, 1.0)
        score += fc * weights['M3_function_call_count']
        
        # Lines of code (normalize to 0-500 scale)
        loc = min(features.get('M4_lines_of_code', 0) / 500.0, 1.0)
        score += loc * weights['M4_lines_of_code']
        
        # Conditionals (normalize to 0-50 scale)
        cond = min(features.get('M12_conditional_count', 0) / 50.0, 1.0)
        score += cond * weights['M12_conditional_count']
        
        # Loops (normalize to 0-20 scale)
        loops = min(features.get('M13_loop_count', 0) / 20.0, 1.0)
        score += loops * weights['M13_loop_count']
        
        # Scale to 0-100
        return score * 100.0
    
    def get_feature_vector(self, code: str, language: str = None) -> List[float]:
        """
        Extract features as a numeric vector for ML input
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            List of 15 numeric feature values
        """
        features = self.extract_all_features(code, language)
        
        # Extract only numeric features in order
        return [
            float(features['M1_cyclomatic_complexity']),
            float(features['M2_nesting_depth']),
            float(features['M3_function_call_count']),
            float(features['M4_lines_of_code']),
            float(features['M5_string_literal_count']),
            float(features['M6_numeric_literal_count']),
            float(features['M7_api_call_count']),
            float(features['M8_dangerous_function_count']),
            float(features['M9_comment_ratio']),
            float(features['M10_import_count']),
            float(features['M11_variable_count']),
            float(features['M12_conditional_count']),
            float(features['M13_loop_count']),
            float(features['M14_exception_handling_count']),
            float(features['M15_code_complexity_score'])
        ]
