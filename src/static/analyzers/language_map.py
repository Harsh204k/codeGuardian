"""
Language to Analyzer Mapper
Routes language strings to appropriate analyzer classes
"""
from typing import Dict, Type, Optional
from .base_analyzer import BaseAnalyzer


class LanguageMapper:
    """
    Maps language identifiers to their corresponding analyzer classes.
    Supports lazy loading to avoid circular imports.
    """
    
    _analyzer_map: Dict[str, Type[BaseAnalyzer]] = {}
    _initialized: bool = False
    
    @classmethod
    def _initialize(cls):
        """Lazy initialization of analyzer mapping"""
        if cls._initialized:
            return
        
        # Import here to avoid circular dependencies
        from .c_analyzer import CAnalyzer
        from .cpp_analyzer import CppAnalyzer
        from .java_analyzer import JavaAnalyzer
        from .python_analyzer import PythonAnalyzer
        from .js_analyzer import JavaScriptAnalyzer
        from .php_analyzer import PhpAnalyzer
        from .go_analyzer import GoAnalyzer
        from .ruby_analyzer import RubyAnalyzer
        
        cls._analyzer_map = {
            'c': CAnalyzer,
            'c++': CppAnalyzer,
            'cpp': CppAnalyzer,
            'java': JavaAnalyzer,
            'python': PythonAnalyzer,
            'py': PythonAnalyzer,
            'javascript': JavaScriptAnalyzer,
            'js': JavaScriptAnalyzer,
            'typescript': JavaScriptAnalyzer,
            'ts': JavaScriptAnalyzer,
            'php': PhpAnalyzer,
            'go': GoAnalyzer,
            'golang': GoAnalyzer,
            'ruby': RubyAnalyzer,
            'rb': RubyAnalyzer
        }
        
        cls._initialized = True
    
    @classmethod
    def get_analyzer_class(cls, language: str) -> Optional[Type[BaseAnalyzer]]:
        """
        Get the analyzer class for a given language
        
        Args:
            language: Language identifier (case-insensitive)
            
        Returns:
            Analyzer class or None if not supported
        """
        cls._initialize()
        return cls._analyzer_map.get(language.lower())
    
    @classmethod
    def get_analyzer(cls, language: str, rule_engine=None) -> Optional[BaseAnalyzer]:
        """
        Instantiate an analyzer for a given language
        
        Args:
            language: Language identifier
            rule_engine: RuleEngine instance to pass to analyzer
            
        Returns:
            Instantiated analyzer or None if language not supported
        """
        analyzer_class = cls.get_analyzer_class(language)
        if analyzer_class:
            return analyzer_class(language, rule_engine)
        return None
    
    @classmethod
    def supported_languages(cls) -> list:
        """
        Get list of all supported languages
        
        Returns:
            List of supported language identifiers
        """
        cls._initialize()
        return list(cls._analyzer_map.keys())
    
    @classmethod
    def is_supported(cls, language: str) -> bool:
        """
        Check if a language is supported
        
        Args:
            language: Language identifier
            
        Returns:
            True if language is supported, False otherwise
        """
        cls._initialize()
        return language.lower() in cls._analyzer_map


def get_analyzer_for_language(language: str, rule_engine=None) -> Optional[BaseAnalyzer]:
    """
    Convenience function to get an analyzer instance
    
    Args:
        language: Language identifier
        rule_engine: Optional RuleEngine instance
        
    Returns:
        Analyzer instance or None
    """
    return LanguageMapper.get_analyzer(language, rule_engine)


def is_language_supported(language: str) -> bool:
    """
    Convenience function to check language support
    
    Args:
        language: Language identifier
        
    Returns:
        True if supported, False otherwise
    """
    return LanguageMapper.is_supported(language)
