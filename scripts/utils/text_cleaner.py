"""
Text cleaning utility module for code preprocessing.

Provides functions for:
- Removing comments from various programming languages
- Normalizing whitespace
- Basic code sanitization
- Code length validation
"""

import re
from typing import Optional


def remove_c_style_comments(code: str) -> str:
    """
    Remove C-style comments (/* */ and //) from code.
    
    Args:
        code: Source code string
        
    Returns:
        Code with comments removed
    """
    # Remove multi-line comments /* */
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # Remove single-line comments //
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    
    return code


def remove_python_comments(code: str) -> str:
    """
    Remove Python comments (#) from code.
    
    Args:
        code: Python source code string
        
    Returns:
        Code with comments removed
    """
    # Remove comments but preserve strings
    lines = []
    for line in code.split('\n'):
        # Simple heuristic: remove # comments but not in strings
        # This is not perfect but works for most cases
        if '#' in line:
            # Check if # is not inside a string
            in_string = False
            string_char = None
            cleaned = []
            
            for i, char in enumerate(line):
                if char in ['"', "'"] and (i == 0 or line[i-1] != '\\'):
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                        string_char = None
                
                if char == '#' and not in_string:
                    break
                
                cleaned.append(char)
            
            lines.append(''.join(cleaned))
        else:
            lines.append(line)
    
    return '\n'.join(lines)


def remove_comments(code: str, language: str) -> str:
    """
    Remove comments from code based on language.
    
    Args:
        code: Source code string
        language: Programming language
        
    Returns:
        Code with comments removed
    """
    language = language.lower() if language else ""
    
    if language in ['python', 'py', 'ruby', 'rb']:
        return remove_python_comments(code)
    elif language in ['c', 'c++', 'cpp', 'java', 'javascript', 'js', 'go', 'php', 'csharp', 'cs', 'c#']:
        return remove_c_style_comments(code)
    else:
        # Default to C-style for unknown languages
        return remove_c_style_comments(code)


def normalize_whitespace(code: str, preserve_structure: bool = True) -> str:
    """
    Normalize whitespace in code.
    
    Args:
        code: Source code string
        preserve_structure: If True, preserve line breaks; if False, compact all whitespace
        
    Returns:
        Code with normalized whitespace
    """
    if preserve_structure:
        # Remove trailing whitespace from each line
        lines = [line.rstrip() for line in code.split('\n')]
        # Remove multiple consecutive blank lines
        cleaned_lines = []
        prev_blank = False
        for line in lines:
            is_blank = not line.strip()
            if is_blank and prev_blank:
                continue
            cleaned_lines.append(line)
            prev_blank = is_blank
        
        return '\n'.join(cleaned_lines)
    else:
        # Compact all whitespace to single spaces
        return ' '.join(code.split())


def remove_empty_lines(code: str) -> str:
    """
    Remove empty lines from code.
    
    Args:
        code: Source code string
        
    Returns:
        Code without empty lines
    """
    lines = [line for line in code.split('\n') if line.strip()]
    return '\n'.join(lines)


def truncate_code(code: str, max_length: int = 10000) -> str:
    """
    Truncate code to a maximum length.
    
    Args:
        code: Source code string
        max_length: Maximum number of characters
        
    Returns:
        Truncated code
    """
    if len(code) <= max_length:
        return code
    
    return code[:max_length] + "\n... [truncated]"


def sanitize_code(code: str, language: str = "unknown", 
                 remove_comments_flag: bool = False,
                 normalize_ws: bool = True,
                 max_length: Optional[int] = None) -> str:
    """
    Sanitize code by applying various cleaning operations.
    
    Args:
        code: Source code string
        language: Programming language
        remove_comments_flag: Whether to remove comments
        normalize_ws: Whether to normalize whitespace
        max_length: Maximum code length (None for no limit)
        
    Returns:
        Sanitized code
    """
    if not code or not isinstance(code, str):
        return ""
    
    # Remove comments if requested
    if remove_comments_flag:
        code = remove_comments(code, language)
    
    # Normalize whitespace
    if normalize_ws:
        code = normalize_whitespace(code, preserve_structure=True)
    
    # Truncate if needed
    if max_length:
        code = truncate_code(code, max_length)
    
    return code.strip()


def is_valid_code(code: str, min_length: int = 10, max_length: int = 100000) -> bool:
    """
    Check if code snippet is valid (not too short or too long).
    
    Args:
        code: Source code string
        min_length: Minimum acceptable length
        max_length: Maximum acceptable length
        
    Returns:
        True if valid, False otherwise
    """
    if not code or not isinstance(code, str):
        return False
    
    code_length = len(code.strip())
    return min_length <= code_length <= max_length


def extract_function_name(code: str, language: str) -> Optional[str]:
    """
    Try to extract function/method name from code (best effort).
    
    Args:
        code: Source code string
        language: Programming language
        
    Returns:
        Function name or None
    """
    language = language.lower() if language else ""
    
    patterns = []
    
    if language in ['c', 'c++', 'cpp']:
        # C/C++ function pattern
        patterns.append(r'(?:static\s+)?(?:inline\s+)?(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{')
    
    elif language in ['java', 'csharp', 'cs', 'c#']:
        # Java/C# method pattern
        patterns.append(r'(?:public|private|protected|static|\s)+[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*\{')
    
    elif language in ['python', 'py']:
        # Python function pattern
        patterns.append(r'def\s+(\w+)\s*\([^)]*\)\s*:')
    
    elif language in ['javascript', 'js']:
        # JavaScript function pattern
        patterns.append(r'function\s+(\w+)\s*\([^)]*\)\s*\{')
        patterns.append(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>')
    
    elif language in ['go']:
        # Go function pattern
        patterns.append(r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\([^)]*\)')
    
    elif language in ['php']:
        # PHP function pattern
        patterns.append(r'function\s+(\w+)\s*\([^)]*\)\s*\{')
    
    elif language in ['ruby', 'rb']:
        # Ruby method pattern
        patterns.append(r'def\s+(\w+)(?:\s+|\()')
    
    # Try all patterns
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    
    return None


def clean_special_chars(text: str) -> str:
    """
    Remove or replace special characters that might cause issues.
    
    Args:
        text: Input text
        
    Returns:
        Cleaned text
    """
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Replace other problematic characters
    replacements = {
        '\r\n': '\n',
        '\r': '\n',
        '\t': '    ',  # Replace tabs with 4 spaces
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    return text


def get_code_statistics(code: str) -> dict:
    """
    Get basic statistics about code snippet.
    
    Args:
        code: Source code string
        
    Returns:
        Dictionary with statistics
    """
    lines = code.split('\n')
    
    return {
        "total_chars": len(code),
        "total_lines": len(lines),
        "non_empty_lines": len([l for l in lines if l.strip()]),
        "avg_line_length": sum(len(l) for l in lines) / len(lines) if lines else 0,
        "max_line_length": max(len(l) for l in lines) if lines else 0
    }
