"""
Static Analyzers Package
Provides language-specific code analysis capabilities
"""
from .base_analyzer import BaseAnalyzer
from .language_map import LanguageMapper, get_analyzer_for_language, is_language_supported

__all__ = [
    'BaseAnalyzer',
    'LanguageMapper',
    'get_analyzer_for_language',
    'is_language_supported'
]
