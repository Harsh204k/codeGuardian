"""
C Language Analyzer for CodeGuardian Static Analysis Engine.

Detects vulnerabilities in C code including:
- Buffer overflows (CWE-120, CWE-119)
- Format string vulnerabilities (CWE-134)
- Integer overflows/underflows (CWE-190)
- Use-after-free and double-free (CWE-416, CWE-415)
- Null pointer dereference (CWE-476)
- Command injection (CWE-78)
- Weak cryptography (CWE-327)

Uses pycparser for AST-based analysis with regex fallback.
"""

import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

try:
    from pycparser import c_parser, c_ast, parse_file
    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False
    logging.warning("pycparser not available - using regex-only fallback for C analysis")

from .base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class CAnalyzer(BaseAnalyzer):
    """
    Static analyzer for C language code.
    
    Detects memory safety issues, format string bugs, command injection,
    and other C-specific vulnerabilities.
    """
    
    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        """
        Initialize C analyzer.
        
        Args:
            rules: Dictionary of vulnerability detection rules
        """
        super().__init__(language="C", rules=rules)
        self.parser = c_parser.CParser() if PYCPARSER_AVAILABLE else None
        
        # Dangerous functions mapping to CWE
        self.dangerous_functions = {
            # Buffer overflow risks
            'strcpy': {'cwe': 'CWE-120', 'severity': 'high', 'confidence': 0.9},
            'strcat': {'cwe': 'CWE-120', 'severity': 'high', 'confidence': 0.9},
            'gets': {'cwe': 'CWE-120', 'severity': 'critical', 'confidence': 0.95},
            'sprintf': {'cwe': 'CWE-120', 'severity': 'high', 'confidence': 0.85},
            'vsprintf': {'cwe': 'CWE-120', 'severity': 'high', 'confidence': 0.85},
            
            # Format string vulnerabilities
            'printf': {'cwe': 'CWE-134', 'severity': 'medium', 'confidence': 0.7},
            'fprintf': {'cwe': 'CWE-134', 'severity': 'medium', 'confidence': 0.7},
            'snprintf': {'cwe': 'CWE-134', 'severity': 'medium', 'confidence': 0.7},
            
            # Command injection
            'system': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.9},
            'popen': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.9},
            'exec': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.85},
            'execl': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.85},
            'execlp': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.85},
            'execv': {'cwe': 'CWE-78', 'severity': 'critical', 'confidence': 0.85},
            
            # Memory management
            'malloc': {'cwe': 'CWE-476', 'severity': 'medium', 'confidence': 0.6},
            'calloc': {'cwe': 'CWE-476', 'severity': 'medium', 'confidence': 0.6},
            'realloc': {'cwe': 'CWE-476', 'severity': 'medium', 'confidence': 0.6},
            'free': {'cwe': 'CWE-416', 'severity': 'high', 'confidence': 0.7},
            
            # Weak crypto
            'DES_': {'cwe': 'CWE-327', 'severity': 'medium', 'confidence': 0.8},
            'MD5': {'cwe': 'CWE-327', 'severity': 'medium', 'confidence': 0.85},
            'SHA1': {'cwe': 'CWE-327', 'severity': 'medium', 'confidence': 0.8},
            'RC4': {'cwe': 'CWE-327', 'severity': 'high', 'confidence': 0.9},
        }
    
    def detect_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in C code.
        
        Args:
            code: C source code to analyze
            
        Returns:
            List of detected vulnerabilities with CWE mappings
        """
        vulnerabilities = []
        
        # Try AST-based analysis if pycparser is available
        if self.parser and PYCPARSER_AVAILABLE:
            try:
                ast_vulns = self._analyze_with_ast(code)
                vulnerabilities.extend(ast_vulns)
            except Exception as e:
                logger.debug(f"AST analysis failed, falling back to regex: {e}")
        
        # Always run regex-based analysis for additional coverage
        regex_vulns = self._analyze_with_regex(code)
        vulnerabilities.extend(regex_vulns)
        
        # Deduplicate based on CWE and line number
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v.get('cwe_id'), v.get('line', 0))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        
        return unique_vulns
    
    def _analyze_with_ast(self, code: str) -> List[Dict[str, Any]]:
        """
        Perform AST-based vulnerability detection.
        
        Args:
            code: C source code
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Preprocess code for parsing (remove directives that might cause issues)
            preprocessed = self._preprocess_for_parsing(code)
            
            # Parse into AST
            ast = self.parser.parse(preprocessed)
            
            # Visitor pattern for AST traversal
            visitor = CVulnerabilityVisitor()
            visitor.visit(ast)
            
            vulnerabilities.extend(visitor.vulnerabilities)
            
        except Exception as e:
            logger.debug(f"AST parsing failed: {e}")
        
        return vulnerabilities
    
    def _preprocess_for_parsing(self, code: str) -> str:
        """
        Preprocess C code for parsing.
        
        Args:
            code: Original C code
            
        Returns:
            Preprocessed code
        """
        # Remove common problematic directives
        lines = code.split('\n')
        processed_lines = []
        
        for line in lines:
            stripped = line.strip()
            # Skip preprocessor directives that might cause parsing issues
            if stripped.startswith('#include') or stripped.startswith('#define'):
                continue
            processed_lines.append(line)
        
        return '\n'.join(processed_lines)
    
    def _analyze_with_regex(self, code: str) -> List[Dict[str, Any]]:
        """
        Perform regex-based vulnerability detection.
        
        Args:
            code: C source code
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Check for dangerous function calls
        for func_name, info in self.dangerous_functions.items():
            pattern = rf'\b{re.escape(func_name)}\s*\('
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'cwe_id': info['cwe'],
                        'severity': info['severity'],
                        'confidence': info['confidence'],
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'message': f"Dangerous function '{func_name}' detected",
                        'function': func_name
                    })
        
        # Buffer overflow patterns
        buffer_overflow_patterns = [
            (r'scanf\s*\(\s*"%s"', 'CWE-120', 0.9, 'Unsafe scanf with %s'),
            (r'gets\s*\(', 'CWE-120', 0.95, 'gets() is always unsafe'),
            (r'strcpy\s*\([^,]+,\s*[^)]+\)', 'CWE-120', 0.85, 'strcpy without bounds checking'),
            (r'strcat\s*\([^,]+,\s*[^)]+\)', 'CWE-120', 0.85, 'strcat without bounds checking'),
        ]
        
        for pattern, cwe, confidence, message in buffer_overflow_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'cwe_id': cwe,
                        'severity': 'high',
                        'confidence': confidence,
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'message': message
                    })
        
        # Format string vulnerabilities
        format_string_patterns = [
            (r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', 'CWE-134', 0.8, 'printf with variable format'),
            (r'fprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', 'CWE-134', 0.8, 'fprintf with variable format'),
            (r'sprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)', 'CWE-134', 0.8, 'sprintf with variable format'),
        ]
        
        for pattern, cwe, confidence, message in format_string_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'cwe_id': cwe,
                        'severity': 'high',
                        'confidence': confidence,
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'message': message
                    })
        
        # Integer overflow risks
        integer_overflow_patterns = [
            (r'\*\s*=\s*[^;]+\+', 'CWE-190', 0.6, 'Potential integer overflow in multiplication'),
            (r'\+\s*=\s*[^;]+\*', 'CWE-190', 0.6, 'Potential integer overflow in addition'),
            (r'malloc\s*\([^)]*\*[^)]*\)', 'CWE-190', 0.7, 'malloc with multiplication - overflow risk'),
        ]
        
        for pattern, cwe, confidence, message in integer_overflow_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'cwe_id': cwe,
                        'severity': 'medium',
                        'confidence': confidence,
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'message': message
                    })
        
        # Use-after-free detection (basic heuristic)
        free_pattern = r'free\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)'
        for line_num, line in enumerate(lines, 1):
            match = re.search(free_pattern, line)
            if match:
                var_name = match.group(1)
                # Check if variable is used after free in subsequent lines
                for future_line_num in range(line_num + 1, min(line_num + 20, len(lines) + 1)):
                    if var_name in lines[future_line_num - 1] and 'free' not in lines[future_line_num - 1]:
                        vulnerabilities.append({
                            'cwe_id': 'CWE-416',
                            'severity': 'critical',
                            'confidence': 0.65,
                            'line': future_line_num,
                            'code_snippet': lines[future_line_num - 1].strip(),
                            'message': f"Potential use-after-free of '{var_name}'"
                        })
                        break
        
        # Double-free detection
        for line_num, line in enumerate(lines, 1):
            match = re.search(free_pattern, line)
            if match:
                var_name = match.group(1)
                # Check for another free of same variable
                for future_line_num in range(line_num + 1, min(line_num + 50, len(lines) + 1)):
                    if re.search(rf'free\s*\(\s*{re.escape(var_name)}\s*\)', lines[future_line_num - 1]):
                        vulnerabilities.append({
                            'cwe_id': 'CWE-415',
                            'severity': 'critical',
                            'confidence': 0.7,
                            'line': future_line_num,
                            'code_snippet': lines[future_line_num - 1].strip(),
                            'message': f"Potential double-free of '{var_name}'"
                        })
                        break
        
        # Null pointer dereference
        null_check_pattern = r'if\s*\(\s*!?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)'
        for line_num, line in enumerate(lines, 1):
            # Look for malloc/calloc without null check
            malloc_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(malloc|calloc)\s*\(', line)
            if malloc_match:
                var_name = malloc_match.group(1)
                # Check next 5 lines for null check
                has_null_check = False
                for check_line_num in range(line_num + 1, min(line_num + 6, len(lines) + 1)):
                    if re.search(rf'if\s*\(\s*!?\s*{re.escape(var_name)}\s*\)', lines[check_line_num - 1]):
                        has_null_check = True
                        break
                
                if not has_null_check:
                    vulnerabilities.append({
                        'cwe_id': 'CWE-476',
                        'severity': 'high',
                        'confidence': 0.7,
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'message': f"Memory allocation without null check for '{var_name}'"
                    })
        
        return vulnerabilities


class CVulnerabilityVisitor:
    """AST visitor for detecting vulnerabilities in C code."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.in_function = None
    
    def visit(self, node):
        """Visit AST node and detect vulnerabilities."""
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node):
        """Visit children of node."""
        for child in node.children():
            self.visit(child)
    
    def visit_FuncCall(self, node):
        """Detect dangerous function calls."""
        if hasattr(node.name, 'name'):
            func_name = node.name.name
            
            # Check against known dangerous functions
            dangerous_funcs = {
                'strcpy': ('CWE-120', 'high', 0.9),
                'strcat': ('CWE-120', 'high', 0.9),
                'gets': ('CWE-120', 'critical', 0.95),
                'system': ('CWE-78', 'critical', 0.9),
                'popen': ('CWE-78', 'critical', 0.9),
            }
            
            if func_name in dangerous_funcs:
                cwe, severity, confidence = dangerous_funcs[func_name]
                self.vulnerabilities.append({
                    'cwe_id': cwe,
                    'severity': severity,
                    'confidence': confidence,
                    'message': f"Dangerous function '{func_name}' detected",
                    'function': func_name
                })
        
        self.generic_visit(node)


# Register analyzer
def get_analyzer(rules: Optional[Dict[str, Any]] = None) -> CAnalyzer:
    """
    Factory function to create C analyzer.
    
    Args:
        rules: Optional rules dictionary
        
    Returns:
        CAnalyzer instance
    """
    return CAnalyzer(rules)
