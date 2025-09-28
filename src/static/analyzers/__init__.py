"""
Multi-language static analysis package for security vulnerability detection.

This package contains individual analyzers for different programming languages:
- Python (bandit)
- C/C++ (cppcheck)
- PHP (phpcs with security rules)
- JavaScript/TypeScript (ESLint with security plugin)
- Go (gosec)

Each analyzer provides consistent output format and can be used independently
or through the multi_analyzer coordinator.
"""

from .multi_analyzer import MultiLanguageAnalyzer

__version__ = "1.0.0"
__all__ = ["MultiLanguageAnalyzer"]
