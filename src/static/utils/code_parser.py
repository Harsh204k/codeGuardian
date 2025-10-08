"""
CodeGuardian Static Analysis - Code Parser

This module provides regex and AST-based code parsing utilities for
vulnerability detection across multiple languages.
"""

import re
import ast
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class CodeElement:
    """Represents a parsed code element."""
    type: str  # function, class, import, etc.
    name: str
    start_line: int
    end_line: int
    code: str
    metadata: Dict[str, Any]


class CodeParser:
    """
    Multi-language code parser supporting regex and AST-based analysis.
    """
    
    def __init__(self, language: str):
        """
        Initialize the parser for a specific language.
        
        Args:
            language: Programming language identifier
        """
        self.language = language.lower()
        
    def parse_python(self, code: str) -> Dict[str, Any]:
        """
        Parse Python code using AST.
        
        Args:
            code: Python source code
            
        Returns:
            Dictionary with parsed elements
        """
        try:
            tree = ast.parse(code)
            
            functions = []
            classes = []
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        'name': node.name,
                        'line': node.lineno,
                        'args': [arg.arg for arg in node.args.args],
                        'decorators': [d.id if isinstance(d, ast.Name) else str(d) for d in node.decorator_list]
                    })
                elif isinstance(node, ast.ClassDef):
                    classes.append({
                        'name': node.name,
                        'line': node.lineno,
                        'bases': [b.id if isinstance(b, ast.Name) else str(b) for b in node.bases]
                    })
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append({'name': alias.name, 'line': node.lineno})
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        imports.append({'name': f"{module}.{alias.name}", 'line': node.lineno})
            
            return {
                'functions': functions,
                'classes': classes,
                'imports': imports,
                'ast': tree
            }
        except SyntaxError as e:
            logger.warning(f"Python syntax error: {e}")
            return self._fallback_parse(code)
    
    def parse_java(self, code: str) -> Dict[str, Any]:
        """
        Parse Java code using regex patterns.
        
        Args:
            code: Java source code
            
        Returns:
            Dictionary with parsed elements
        """
        # Method declarations
        method_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(\w+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        methods = []
        for match in re.finditer(method_pattern, code):
            methods.append({
                'return_type': match.group(1),
                'name': match.group(2),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Class declarations
        class_pattern = r'(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?'
        classes = []
        for match in re.finditer(class_pattern, code):
            classes.append({
                'name': match.group(1),
                'extends': match.group(2),
                'implements': match.group(3),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Imports
        import_pattern = r'import\s+([\w\.]+);'
        imports = []
        for match in re.finditer(import_pattern, code):
            imports.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        return {
            'methods': methods,
            'classes': classes,
            'imports': imports
        }
    
    def parse_cpp(self, code: str) -> Dict[str, Any]:
        """
        Parse C/C++ code using regex patterns.
        
        Args:
            code: C/C++ source code
            
        Returns:
            Dictionary with parsed elements
        """
        # Function declarations
        func_pattern = r'(?:static|inline|extern|virtual)?\s*(\w+)\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{'
        functions = []
        for match in re.finditer(func_pattern, code):
            functions.append({
                'return_type': match.group(1),
                'name': match.group(2),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Class declarations
        class_pattern = r'class\s+(\w+)(?:\s*:\s*(?:public|private|protected)\s+(\w+))?'
        classes = []
        for match in re.finditer(class_pattern, code):
            classes.append({
                'name': match.group(1),
                'inherits': match.group(2),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Includes
        include_pattern = r'#include\s*[<"]([^>"]+)[>"]'
        includes = []
        for match in re.finditer(include_pattern, code):
            includes.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        return {
            'functions': functions,
            'classes': classes,
            'includes': includes
        }
    
    def parse_javascript(self, code: str) -> Dict[str, Any]:
        """
        Parse JavaScript/TypeScript code using regex patterns.
        
        Args:
            code: JavaScript/TypeScript source code
            
        Returns:
            Dictionary with parsed elements
        """
        # Function declarations
        func_pattern = r'(?:function|async\s+function)\s+(\w+)\s*\([^)]*\)'
        arrow_func_pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>'
        
        functions = []
        for match in re.finditer(func_pattern, code):
            functions.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1,
                'type': 'function'
            })
        for match in re.finditer(arrow_func_pattern, code):
            functions.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1,
                'type': 'arrow'
            })
        
        # Class declarations
        class_pattern = r'class\s+(\w+)(?:\s+extends\s+(\w+))?'
        classes = []
        for match in re.finditer(class_pattern, code):
            classes.append({
                'name': match.group(1),
                'extends': match.group(2),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Imports
        import_pattern = r'import\s+(?:(?:\{[^}]+\}|\w+)\s+from\s+)?["\']([^"\']+)["\']'
        require_pattern = r'require\s*\(\s*["\']([^"\']+)["\']\s*\)'
        
        imports = []
        for match in re.finditer(import_pattern, code):
            imports.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1,
                'type': 'import'
            })
        for match in re.finditer(require_pattern, code):
            imports.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1,
                'type': 'require'
            })
        
        return {
            'functions': functions,
            'classes': classes,
            'imports': imports
        }
    
    def parse_php(self, code: str) -> Dict[str, Any]:
        """
        Parse PHP code using regex patterns.
        
        Args:
            code: PHP source code
            
        Returns:
            Dictionary with parsed elements
        """
        # Function declarations
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)'
        functions = []
        for match in re.finditer(func_pattern, code):
            functions.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Class declarations
        class_pattern = r'class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?'
        classes = []
        for match in re.finditer(class_pattern, code):
            classes.append({
                'name': match.group(1),
                'extends': match.group(2),
                'implements': match.group(3),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Includes/requires
        include_pattern = r'(?:include|require|include_once|require_once)\s*\(?["\']([^"\']+)["\']\)?'
        includes = []
        for match in re.finditer(include_pattern, code):
            includes.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        return {
            'functions': functions,
            'classes': classes,
            'includes': includes
        }
    
    def parse_go(self, code: str) -> Dict[str, Any]:
        """
        Parse Go code using regex patterns.
        
        Args:
            code: Go source code
            
        Returns:
            Dictionary with parsed elements
        """
        # Function declarations
        func_pattern = r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\([^)]*\)(?:\s*\([^)]*\))?'
        functions = []
        for match in re.finditer(func_pattern, code):
            functions.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Struct declarations
        struct_pattern = r'type\s+(\w+)\s+struct'
        structs = []
        for match in re.finditer(struct_pattern, code):
            structs.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        # Imports
        import_pattern = r'import\s+(?:\(([^)]+)\)|"([^"]+)")'
        imports = []
        for match in re.finditer(import_pattern, code):
            if match.group(1):  # Multiple imports
                for imp in re.findall(r'"([^"]+)"', match.group(1)):
                    imports.append({'name': imp, 'line': code[:match.start()].count('\n') + 1})
            elif match.group(2):  # Single import
                imports.append({'name': match.group(2), 'line': code[:match.start()].count('\n') + 1})
        
        return {
            'functions': functions,
            'structs': structs,
            'imports': imports
        }
    
    def _fallback_parse(self, code: str) -> Dict[str, Any]:
        """
        Fallback parser for when language-specific parsing fails.
        
        Args:
            code: Source code
            
        Returns:
            Dictionary with basic parsed elements
        """
        # Generic function detection
        func_pattern = r'(?:def|function|func|sub|proc)\s+(\w+)'
        functions = []
        for match in re.finditer(func_pattern, code, re.IGNORECASE):
            functions.append({
                'name': match.group(1),
                'line': code[:match.start()].count('\n') + 1
            })
        
        return {
            'functions': functions,
            'classes': [],
            'imports': []
        }
    
    def parse(self, code: str) -> Dict[str, Any]:
        """
        Parse code using language-specific parser.
        
        Args:
            code: Source code
            
        Returns:
            Dictionary with parsed elements
        """
        parsers = {
            'python': self.parse_python,
            'java': self.parse_java,
            'cpp': self.parse_cpp,
            'c': self.parse_cpp,
            'javascript': self.parse_javascript,
            'typescript': self.parse_javascript,
            'php': self.parse_php,
            'go': self.parse_go,
        }
        
        parser_func = parsers.get(self.language, self._fallback_parse)
        return parser_func(code)
    
    def extract_string_literals(self, code: str) -> List[Tuple[str, int]]:
        """
        Extract all string literals from code.
        
        Args:
            code: Source code
            
        Returns:
            List of (string_value, line_number) tuples
        """
        # Match both single and double quoted strings
        pattern = r'(["\'])(?:(?=(\\?))\2.)*?\1'
        matches = []
        
        for match in re.finditer(pattern, code):
            line_no = code[:match.start()].count('\n') + 1
            matches.append((match.group(0), line_no))
        
        return matches
    
    def extract_comments(self, code: str) -> List[Tuple[str, int]]:
        """
        Extract comments from code.
        
        Args:
            code: Source code
            
        Returns:
            List of (comment_text, line_number) tuples
        """
        comments = []
        
        # Single-line comments (// or #)
        single_pattern = r'(?://|#)(.*)$'
        for match in re.finditer(single_pattern, code, re.MULTILINE):
            line_no = code[:match.start()].count('\n') + 1
            comments.append((match.group(1).strip(), line_no))
        
        # Multi-line comments (/* */ or """ """)
        multi_pattern = r'/\*.*?\*/|""".*?"""'
        for match in re.finditer(multi_pattern, code, re.DOTALL):
            line_no = code[:match.start()].count('\n') + 1
            comments.append((match.group(0), line_no))
        
        return comments
    
    def find_dangerous_patterns(self, code: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """
        Find occurrences of dangerous patterns in code.
        
        Args:
            code: Source code
            patterns: List of regex patterns to search for
            
        Returns:
            List of matches with line numbers
        """
        matches = []
        
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
                for match in regex.finditer(code):
                    line_no = code[:match.start()].count('\n') + 1
                    matches.append({
                        'pattern': pattern,
                        'match': match.group(0),
                        'line': line_no,
                        'column': match.start() - code.rfind('\n', 0, match.start())
                    })
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        return matches
