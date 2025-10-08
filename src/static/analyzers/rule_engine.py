"""
Rule Engine for YAML-based Vulnerability Detection
Loads and executes detection rules across multiple languages and CWE types
"""
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging


logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Manages loading and execution of YAML-based vulnerability detection rules.
    Supports multiple rule types: regex, api_call, ast_pattern, keyword, metric_threshold
    """
    
    def __init__(self, rules_dir: Path):
        """
        Initialize rule engine
        
        Args:
            rules_dir: Path to rules directory containing YAML files
        """
        self.rules_dir = Path(rules_dir)
        self.language_rules: Dict[str, List[Dict[str, Any]]] = {}
        self.shared_rules: List[Dict[str, Any]] = []
        self.cwe_mapping: Dict[str, List[Dict[str, Any]]] = {}
        
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
        
    def load_all_rules(self) -> None:
        """Load all language-specific and shared rules"""
        logger.info("Loading all vulnerability detection rules...")
        
        # Load language-specific rules
        language_files = ['cpp.yml', 'java.yml', 'python.yml', 'php.yml', 
                         'js.yml', 'go.yml', 'ruby.yml']
        
        for lang_file in language_files:
            lang_path = self.rules_dir / lang_file
            if lang_path.exists():
                language = lang_file.replace('.yml', '')
                self.language_rules[language] = self._load_yaml_file(lang_path)
                logger.info(f"Loaded {len(self.language_rules[language])} rules for {language}")
        
        # Load shared CWE rules
        shared_dir = self.rules_dir / 'shared'
        if shared_dir.exists():
            for cwe_file in shared_dir.glob('cwe*.yml'):
                rules = self._load_yaml_file(cwe_file)
                self.shared_rules.extend(rules)
                
                # Index by CWE ID for quick lookup
                for rule in rules:
                    cwe_id = rule.get('cwe_id')
                    if cwe_id:
                        if cwe_id not in self.cwe_mapping:
                            self.cwe_mapping[cwe_id] = []
                        self.cwe_mapping[cwe_id].append(rule)
            
            logger.info(f"Loaded {len(self.shared_rules)} shared CWE rules")
    
    def _load_yaml_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Load rules from a YAML file
        
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
            
            # Handle both single rule and list of rules
            if isinstance(data, dict):
                if 'rules' in data:
                    return data['rules']
                else:
                    return [data]
            elif isinstance(data, list):
                return data
            
            return []
            
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return []
    
    def load_rules_for_language(self, language: str) -> List[Dict[str, Any]]:
        """
        Load all applicable rules for a specific language
        
        Args:
            language: Language identifier
            
        Returns:
            Combined list of language-specific and shared rules
        """
        # Ensure rules are loaded
        if not self.language_rules and not self.shared_rules:
            self.load_all_rules()
        
        language = language.lower()
        
        # Get language-specific rules
        lang_rules = self.language_rules.get(language, [])
        
        # Add applicable shared rules
        all_rules = lang_rules.copy()
        
        # Filter shared rules by language applicability
        for rule in self.shared_rules:
            applicable_languages = rule.get('languages', [])
            if not applicable_languages or language in applicable_languages or \
               'all' in applicable_languages:
                all_rules.append(rule)
        
        return all_rules
    
    def execute_rule(self, rule: Dict[str, Any], code: str, 
                    metrics: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute a single rule against code
        
        Args:
            rule: Rule dictionary
            code: Source code to analyze
            metrics: Optional pre-computed metrics for metric_threshold rules
            
        Returns:
            List of vulnerability findings
        """
        rule_type = rule.get('type', 'regex')
        
        if rule_type == 'regex':
            return self._execute_regex_rule(rule, code)
        elif rule_type == 'api_call':
            return self._execute_api_call_rule(rule, code)
        elif rule_type == 'keyword':
            return self._execute_keyword_rule(rule, code)
        elif rule_type == 'ast_pattern':
            return self._execute_ast_pattern_rule(rule, code)
        elif rule_type == 'metric_threshold':
            return self._execute_metric_threshold_rule(rule, code, metrics)
        else:
            logger.warning(f"Unknown rule type: {rule_type}")
            return []
    
    def _execute_regex_rule(self, rule: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
        """Execute regex-based rule"""
        findings = []
        pattern = rule.get('pattern')
        
        if not pattern:
            return findings
        
        try:
            matches = re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE)
            
            for match in matches:
                # Calculate line number
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    'rule_id': rule.get('id', 'unknown'),
                    'cwe_id': rule.get('cwe_id'),
                    'severity': rule.get('severity', 'MEDIUM'),
                    'description': rule.get('description', ''),
                    'line': line_num,
                    'matched_text': match.group(0)[:100],  # Truncate to 100 chars
                    'remediation': rule.get('remediation', ''),
                    'confidence': rule.get('confidence', 'MEDIUM')
                })
        
        except re.error as e:
            logger.error(f"Regex error in rule {rule.get('id')}: {e}")
        
        return findings
    
    def _execute_api_call_rule(self, rule: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
        """Execute API call detection rule"""
        findings = []
        api_names = rule.get('api_names', [])
        
        if not api_names:
            return findings
        
        for api_name in api_names:
            # Pattern: api_name followed by (
            pattern = rf'\b{re.escape(api_name)}\s*\('
            matches = re.finditer(pattern, code, re.MULTILINE)
            
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    'rule_id': rule.get('id', 'unknown'),
                    'cwe_id': rule.get('cwe_id'),
                    'severity': rule.get('severity', 'MEDIUM'),
                    'description': rule.get('description', '').replace('{api}', api_name),
                    'line': line_num,
                    'matched_text': match.group(0),
                    'remediation': rule.get('remediation', ''),
                    'confidence': rule.get('confidence', 'MEDIUM')
                })
        
        return findings
    
    def _execute_keyword_rule(self, rule: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
        """Execute keyword-based rule"""
        findings = []
        keywords = rule.get('keywords', [])
        
        if not keywords:
            return findings
        
        # Build pattern from keywords
        keyword_pattern = '|'.join([re.escape(kw) for kw in keywords])
        pattern = rf'\b({keyword_pattern})\b'
        
        matches = re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append({
                'rule_id': rule.get('id', 'unknown'),
                'cwe_id': rule.get('cwe_id'),
                'severity': rule.get('severity', 'LOW'),
                'description': rule.get('description', ''),
                'line': line_num,
                'matched_text': match.group(0),
                'remediation': rule.get('remediation', ''),
                'confidence': rule.get('confidence', 'LOW')
            })
        
        return findings
    
    def _execute_ast_pattern_rule(self, rule: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
        """
        Execute AST pattern-based rule
        Note: This is a simplified version using regex patterns
        For true AST analysis, integrate language-specific parsers
        """
        findings = []
        pattern = rule.get('pattern')
        
        if not pattern:
            return findings
        
        # Use regex as fallback for AST patterns
        return self._execute_regex_rule(rule, code)
    
    def _execute_metric_threshold_rule(self, rule: Dict[str, Any], code: str,
                                      metrics: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute metric threshold rule"""
        findings = []
        
        if not metrics:
            return findings
        
        metric_name = rule.get('metric')
        threshold = rule.get('threshold')
        operator = rule.get('operator', '>')
        
        if not metric_name or threshold is None:
            return findings
        
        metric_value = metrics.get(metric_name)
        
        if metric_value is None:
            return findings
        
        # Check threshold
        triggered = False
        if operator == '>':
            triggered = metric_value > threshold
        elif operator == '>=':
            triggered = metric_value >= threshold
        elif operator == '<':
            triggered = metric_value < threshold
        elif operator == '<=':
            triggered = metric_value <= threshold
        elif operator == '==':
            triggered = metric_value == threshold
        
        if triggered:
            findings.append({
                'rule_id': rule.get('id', 'unknown'),
                'cwe_id': rule.get('cwe_id'),
                'severity': rule.get('severity', 'INFO'),
                'description': rule.get('description', '').format(
                    metric=metric_name,
                    value=metric_value,
                    threshold=threshold
                ),
                'line': 0,  # Metric-based, no specific line
                'matched_text': f'{metric_name}={metric_value}',
                'remediation': rule.get('remediation', ''),
                'confidence': rule.get('confidence', 'HIGH')
            })
        
        return findings
    
    def execute_all_rules(self, rules: List[Dict[str, Any]], code: str,
                         metrics: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute all rules against code
        
        Args:
            rules: List of rules to execute
            code: Source code
            metrics: Optional pre-computed metrics
            
        Returns:
            Combined list of all findings
        """
        all_findings = []
        
        for rule in rules:
            findings = self.execute_rule(rule, code, metrics)
            all_findings.extend(findings)
        
        return all_findings
    
    def get_rules_by_cwe(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Get all rules associated with a specific CWE
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')
            
        Returns:
            List of matching rules
        """
        return self.cwe_mapping.get(cwe_id, [])
    
    def get_supported_cwes(self) -> Set[str]:
        """
        Get set of all CWEs covered by loaded rules
        
        Returns:
            Set of CWE identifiers
        """
        return set(self.cwe_mapping.keys())
