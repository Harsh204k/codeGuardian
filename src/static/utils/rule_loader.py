"""
CodeGuardian Static Analysis - Rule Loader and Validator

This module handles loading, validation, and merging of YAML-based vulnerability
detection rules from multiple sources.
"""

import yaml
import json
import jsonschema
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class RuleLoader:
    """
    Loads and validates YAML-based vulnerability detection rules.
    Supports loading from individual files, directories, and CWE-specific rules.
    """
    
    def __init__(self, rules_dir: Optional[Path] = None, schema_path: Optional[Path] = None):
        """
        Initialize the rule loader.
        
        Args:
            rules_dir: Path to the rules directory
            schema_path: Path to the rule JSON schema file
        """
        if rules_dir is None:
            # Default to src/static/rules
            rules_dir = Path(__file__).parent.parent / "rules"
        
        if schema_path is None:
            schema_path = rules_dir / "rule_schema.json"
            
        self.rules_dir = Path(rules_dir)
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
        self._rule_cache: Dict[str, List[Dict[str, Any]]] = {}
        
    def _load_schema(self) -> Optional[Dict[str, Any]]:
        """Load and parse the rule schema JSON."""
        if not self.schema_path.exists():
            logger.warning(f"Rule schema not found at {self.schema_path}")
            return None
            
        try:
            with open(self.schema_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load rule schema: {e}")
            return None
    
    def load_rules_for_language(self, language: str, include_shared: bool = True) -> List[Dict[str, Any]]:
        """
        Load all rules for a specific language.
        
        Args:
            language: Programming language identifier (e.g., 'python', 'java')
            include_shared: Whether to include shared/cross-language rules
            
        Returns:
            List of rule dictionaries
        """
        cache_key = f"{language}:{include_shared}"
        if cache_key in self._rule_cache:
            return self._rule_cache[cache_key]
            
        rules = []
        
        # Load language-specific rules
        lang_file = self.rules_dir / f"{language}.yml"
        if lang_file.exists():
            rules.extend(self._load_yaml_file(lang_file))
            
        # Load CWE-specific rules
        cwe_dir = self.rules_dir / "cwe"
        if cwe_dir.exists():
            for cwe_file in cwe_dir.glob("*.yml"):
                cwe_rules = self._load_yaml_file(cwe_file)
                # Filter rules applicable to this language
                filtered_rules = [
                    r for r in cwe_rules
                    if self._is_rule_applicable(r, language)
                ]
                rules.extend(filtered_rules)
        
        # Load shared rules
        if include_shared:
            shared_dir = self.rules_dir / "shared"
            if shared_dir.exists():
                for shared_file in shared_dir.glob("*.yml"):
                    shared_rules = self._load_yaml_file(shared_file)
                    filtered_rules = [
                        r for r in shared_rules
                        if self._is_rule_applicable(r, language)
                    ]
                    rules.extend(filtered_rules)
        
        # Validate all loaded rules
        validated_rules = []
        for rule in rules:
            if self.validate_rule(rule):
                validated_rules.append(rule)
        
        # Cache the results
        self._rule_cache[cache_key] = validated_rules
        
        return validated_rules
    
    def load_rules_by_cwe(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Load all rules for a specific CWE.
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')
            
        Returns:
            List of rule dictionaries
        """
        rules = []
        
        # Check CWE-specific file
        cwe_file = self.rules_dir / "cwe" / f"{cwe_id}.yml"
        if cwe_file.exists():
            rules.extend(self._load_yaml_file(cwe_file))
        
        # Search through all rule files for this CWE
        for rule_file in self.rules_dir.glob("**/*.yml"):
            file_rules = self._load_yaml_file(rule_file)
            for rule in file_rules:
                if rule.get('cwe_id') == cwe_id:
                    rules.append(rule)
        
        return rules
    
    def load_all_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load all rules organized by language.
        
        Returns:
            Dictionary mapping language to list of rules
        """
        languages = ['python', 'java', 'cpp', 'c', 'javascript', 'typescript', 
                    'php', 'go', 'ruby', 'csharp']
        
        all_rules = {}
        for lang in languages:
            all_rules[lang] = self.load_rules_for_language(lang)
        
        return all_rules
    
    def _load_yaml_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Load and parse a YAML rule file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            List of rule dictionaries
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
            if not data:
                return []
                
            # Handle both formats: {rules: [...]} and direct list
            if isinstance(data, dict) and 'rules' in data:
                return data['rules']
            elif isinstance(data, list):
                return data
            else:
                logger.warning(f"Unexpected format in {file_path}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return []
    
    def _is_rule_applicable(self, rule: Dict[str, Any], language: str) -> bool:
        """
        Check if a rule is applicable to a given language.
        
        Args:
            rule: Rule dictionary
            language: Target language
            
        Returns:
            True if rule applies to language
        """
        rule_lang = rule.get('language', 'all')
        
        if rule_lang == 'all':
            return True
            
        # Handle multiple languages
        if isinstance(rule_lang, list):
            return language in rule_lang or language.lower() in [l.lower() for l in rule_lang]
            
        return rule_lang.lower() == language.lower()
    
    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Validate a rule against the JSON schema.
        
        Args:
            rule: Rule dictionary to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not self.schema:
            # If no schema, do basic validation
            required_fields = ['id', 'name', 'cwe_id', 'severity', 'type', 'description']
            return all(field in rule for field in required_fields)
        
        try:
            # Validate against schema
            jsonschema.validate(instance={'rules': [rule]}, schema=self.schema)
            return True
        except jsonschema.exceptions.ValidationError as e:
            logger.warning(f"Rule validation failed for {rule.get('id', 'unknown')}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Find a specific rule by its ID.
        
        Args:
            rule_id: Unique rule identifier
            
        Returns:
            Rule dictionary or None if not found
        """
        for rule_file in self.rules_dir.glob("**/*.yml"):
            rules = self._load_yaml_file(rule_file)
            for rule in rules:
                if rule.get('id') == rule_id:
                    return rule
        return None
    
    def merge_rules(self, *rule_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge multiple rule lists, removing duplicates by ID.
        
        Args:
            *rule_lists: Variable number of rule lists
            
        Returns:
            Merged list of unique rules
        """
        seen_ids = set()
        merged = []
        
        for rule_list in rule_lists:
            for rule in rule_list:
                rule_id = rule.get('id')
                if rule_id and rule_id not in seen_ids:
                    seen_ids.add(rule_id)
                    merged.append(rule)
        
        return merged
    
    def get_rules_by_severity(self, severity: str, language: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all rules of a specific severity level.
        
        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            language: Optional language filter
            
        Returns:
            List of matching rules
        """
        if language:
            rules = self.load_rules_for_language(language)
        else:
            all_rules = self.load_all_rules()
            rules = []
            for lang_rules in all_rules.values():
                rules.extend(lang_rules)
        
        return [r for r in rules if r.get('severity', '').upper() == severity.upper()]
    
    def clear_cache(self):
        """Clear the internal rule cache."""
        self._rule_cache.clear()
