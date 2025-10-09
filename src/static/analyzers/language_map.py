"""
Language Mapper for Static Analyzers
Maps programming languages to their respective analyzer classes
"""
from typing import Optional, Dict, Type
import logging

logger = logging.getLogger(__name__)


class LanguageMapper:
    """Maps programming languages to analyzer classes"""
    
    LANGUAGE_ALIASES = {
        'python': ['python', 'py', 'python3'],
        'java': ['java'],
        'javascript': ['javascript', 'js', 'typescript', 'ts'],
        'c': ['c'],
        'cpp': ['cpp', 'c++', 'cxx'],
        'php': ['php'],
        'go': ['go', 'golang'],
        'ruby': ['ruby', 'rb'],
        'csharp': ['csharp', 'c#', 'cs']
    }
    
    @classmethod
    def normalize_language(cls, language: str) -> Optional[str]:
        """
        Normalize language name to canonical form
        
        Args:
            language: Raw language string
            
        Returns:
            Normalized language name or None if unsupported
        """
        if not language:
            return None
        
        lang_lower = language.lower().strip()
        
        for canonical, aliases in cls.LANGUAGE_ALIASES.items():
            if lang_lower in aliases:
                return canonical
        
        return None
    
    @classmethod
    def is_supported(cls, language: str) -> bool:
        """Check if language is supported"""
        return cls.normalize_language(language) is not None
    
    @classmethod
    def get_analyzer_class(cls, language: str) -> Optional[Type]:
        """
        Get analyzer class for a language
        
        Args:
            language: Programming language
            
        Returns:
            Analyzer class or None if unsupported
        """
        normalized = cls.normalize_language(language)
        
        if not normalized:
            return None
        
        try:
            if normalized == 'python':
                from .python_analyzer import PythonAnalyzer
                return PythonAnalyzer
            elif normalized == 'java':
                from .java_analyzer import JavaAnalyzer
                return JavaAnalyzer
            elif normalized == 'javascript':
                from .js_analyzer import JSAnalyzer
                return JSAnalyzer
            elif normalized == 'c':
                from .c_analyzer import CAnalyzer
                return CAnalyzer
            elif normalized == 'cpp':
                from .cpp_analyzer import CppAnalyzer
                return CppAnalyzer
            elif normalized == 'php':
                from .php_analyzer import PHPAnalyzer
                return PHPAnalyzer
            elif normalized == 'go':
                from .go_analyzer import GoAnalyzer
                return GoAnalyzer
            elif normalized == 'ruby':
                from .ruby_analyzer import RubyAnalyzer
                return RubyAnalyzer
            elif normalized == 'csharp':
                # CSharp analyzer might not exist, return None
                return None
            else:
                return None
        except ImportError as e:
            logger.warning(f"Failed to import analyzer for {normalized}: {e}")
            return None


def get_analyzer_for_language(language: str, rule_engine=None):
    """
    Get an analyzer instance for a specific language
    
    Args:
        language: Programming language
        rule_engine: Optional RuleEngine instance
        
    Returns:
        Analyzer instance or None if unsupported
    """
    analyzer_class = LanguageMapper.get_analyzer_class(language)
    
    if analyzer_class:
        try:
            return analyzer_class(rule_engine)
        except Exception as e:
            logger.error(f"Failed to instantiate analyzer for {language}: {e}")
            return None
    
    return None


def is_language_supported(language: str) -> bool:
    """
    Check if a language is supported
    
    Args:
        language: Programming language
        
    Returns:
        True if supported, False otherwise
    """
    return LanguageMapper.is_supported(language)


def get_supported_languages() -> Dict[str, list]:
    """
    Get all supported languages and their aliases
    
    Returns:
        Dictionary mapping canonical names to aliases
    """
    return LanguageMapper.LANGUAGE_ALIASES.copy()
