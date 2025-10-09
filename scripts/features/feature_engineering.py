#!/usr/bin/env python3
"""
Phase 2.2 Enhanced: Advanced Feature Engineering Module
========================================================

Production-grade feature extraction with:
- Basic code metrics (LOC, tokens, avg line length, comment density)
- Lexical features (keywords, identifiers, literals, operators)
- Advanced complexity metrics (cyclomatic complexity, nesting depth, AST depth)
- Token diversity and uniqueness metrics
- Entropy-based features (Shannon entropy, identifier entropy)
- Ratio-based features (comment/code, identifier/keyword, etc.)
- Chunked processing for scalability
- CSV export for ML models

Outputs:
- datasets/features/features_static.csv: Feature matrix for ML training
- datasets/features/stats_features.json: Feature statistics
- datasets/features/features_all.jsonl: Feature-enriched records (optional)

Author: CodeGuardian Team
Version: 3.1.0 (Enhanced)
"""

import argparse
import logging
import re
import math
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import Counter, defaultdict
from datetime import datetime
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import (
    chunked_read_jsonl, chunked_write_jsonl,
    write_json, ensure_dir
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ====================================================================
# KEYWORDS AND PATTERNS
# ====================================================================

# Common programming keywords across languages
KEYWORDS = {
    'if', 'else', 'elif', 'for', 'while', 'do', 'switch', 'case', 'break', 
    'continue', 'return', 'function', 'def', 'class', 'struct', 'enum', 
    'interface', 'public', 'private', 'protected', 'static', 'final', 
    'const', 'var', 'let', 'try', 'catch', 'finally', 'throw', 'throws', 
    'import', 'include', 'using', 'namespace', 'package', 'void', 'int', 
    'float', 'double', 'char', 'string', 'bool', 'true', 'false', 'null', 
    'nullptr', 'new', 'delete', 'malloc', 'free', 'async', 'await', 'yield',
    'lambda', 'with', 'as', 'in', 'is', 'not', 'and', 'or', 'goto', 'typedef'
}

# Control flow keywords for cyclomatic complexity
CONTROL_FLOW_KEYWORDS = {
    'if', 'elif', 'else', 'for', 'while', 'do', 'switch', 'case', 
    'catch', 'except', 'unless', 'until'
}


# ====================================================================
# BASIC CODE METRICS
# ====================================================================

def extract_code_metrics(code: str) -> Dict[str, float]:
    """
    Extract basic code metrics.
    
    Args:
        code: Source code string
        
    Returns:
        Dictionary of code metrics
    """
    lines = code.split('\n')
    non_empty_lines = [line for line in lines if line.strip()]
    
    # Lines of code
    loc = len(non_empty_lines)
    total_lines = len(lines)
    
    # Tokenize (simple word-based)
    tokens = re.findall(r'\w+', code)
    num_tokens = len(tokens)
    
    # Average line length
    avg_line_len = sum(len(line) for line in non_empty_lines) / loc if loc > 0 else 0
    
    # Max line length
    max_line_len = max((len(line) for line in lines), default=0)
    
    # Comment density (C-style, Python-style, multi-line)
    comment_lines = 0
    in_multiline_comment = False
    
    for line in lines:
        stripped = line.strip()
        
        # Toggle multiline comment state
        if '/*' in stripped:
            in_multiline_comment = True
        if '*/' in stripped:
            in_multiline_comment = False
            comment_lines += 1
            continue
        
        # Count single-line and multiline comments
        if in_multiline_comment or stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            comment_lines += 1
    
    comment_density = comment_lines / total_lines if total_lines > 0 else 0
    
    # Function length (approximate)
    function_length = loc
    
    return {
        'loc': loc,
        'total_lines': total_lines,
        'num_tokens': num_tokens,
        'avg_line_len': round(avg_line_len, 2),
        'max_line_len': max_line_len,
        'comment_density': round(comment_density, 4),
        'function_length': function_length
    }


# ====================================================================
# LEXICAL FEATURES
# ====================================================================

def extract_lexical_features(code: str) -> Dict[str, int]:
    """
    Extract lexical features from code.
    
    Args:
        code: Source code string
        
    Returns:
        Dictionary of lexical features
    """
    tokens = re.findall(r'\w+', code.lower())
    
    # Keyword counts
    keyword_count = sum(1 for token in tokens if token in KEYWORDS)
    
    # Identifier count (alphanumeric tokens not keywords)
    identifier_count = sum(1 for token in tokens if token not in KEYWORDS and token.isalpha())
    
    # Numeric literals
    numeric_count = len(re.findall(r'\b\d+\.?\d*\b', code))
    
    # String literals (simple approximation)
    string_count = code.count('"') // 2 + code.count("'") // 2
    
    # Special characters
    special_char_count = len(re.findall(r'[{}()\[\];,.]', code))
    
    # Operators
    operator_count = len(re.findall(r'[+\-*/%=<>!&|^~]', code))
    
    return {
        'keyword_count': keyword_count,
        'identifier_count': identifier_count,
        'numeric_count': numeric_count,
        'string_count': string_count,
        'special_char_count': special_char_count,
        'operator_count': operator_count
    }


# ====================================================================
# COMPLEXITY METRICS (Enhanced)
# ====================================================================

def calculate_cyclomatic_complexity(code: str) -> int:
    """
    Calculate cyclomatic complexity (McCabe metric).
    
    Formula: M = E - N + 2P
    Approximation: count decision points
    
    Args:
        code: Source code string
        
    Returns:
        Cyclomatic complexity
    """
    # Start with base complexity of 1
    complexity = 1
    
    # Count control flow keywords (case-insensitive)
    code_lower = code.lower()
    for keyword in CONTROL_FLOW_KEYWORDS:
        complexity += len(re.findall(r'\b' + keyword + r'\b', code_lower))
    
    # Count logical operators (decision points)
    complexity += code.count('&&')
    complexity += code.count('||')
    complexity += code.count('and ')
    complexity += code.count(' or ')
    complexity += code.count('?')  # Ternary operator
    
    return complexity


def calculate_nesting_depth(code: str) -> int:
    """
    Calculate maximum nesting depth based on braces/brackets.
    
    Args:
        code: Source code string
        
    Returns:
        Maximum nesting depth
    """
    max_depth = 0
    current_depth = 0
    
    for char in code:
        if char in '{([':
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char in '})]':
            current_depth = max(0, current_depth - 1)
    
    return max_depth


def calculate_ast_depth(code: str) -> int:
    """
    Calculate approximate AST depth using indentation levels.
    
    For languages with significant indentation (Python) or braces (C/Java),
    this approximates the abstract syntax tree depth.
    
    Args:
        code: Source code string
        
    Returns:
        Approximate AST depth
    """
    max_indent = 0
    
    lines = code.split('\n')
    for line in lines:
        if not line.strip():
            continue
        
        # Count leading whitespace
        indent = len(line) - len(line.lstrip())
        
        # Convert tabs to spaces (assume 4 spaces per tab)
        indent += line.count('\t') * 3
        
        max_indent = max(max_indent, indent)
    
    # Convert indent to depth (assume 4 spaces per level)
    ast_depth = max_indent // 4 + 1
    
    return ast_depth


def calculate_conditional_count(code: str) -> int:
    """Count conditional statements (if, else if, ternary)."""
    count = 0
    code_lower = code.lower()
    
    count += len(re.findall(r'\bif\b', code_lower))
    count += len(re.findall(r'\belif\b', code_lower))
    count += len(re.findall(r'\belse\s+if\b', code_lower))
    count += code.count('?')  # Ternary
    
    return count


def calculate_loop_count(code: str) -> int:
    """Count loop statements (for, while, do-while)."""
    count = 0
    code_lower = code.lower()
    
    count += len(re.findall(r'\bfor\b', code_lower))
    count += len(re.findall(r'\bwhile\b', code_lower))
    count += len(re.findall(r'\bdo\b', code_lower))
    count += len(re.findall(r'\bforeach\b', code_lower))
    
    return count


# ====================================================================
# DIVERSITY AND ENTROPY METRICS
# ====================================================================

def calculate_token_diversity(code: str) -> float:
    """
    Calculate token diversity (unique tokens / total tokens).
    
    Higher diversity = more varied vocabulary.
    
    Args:
        code: Source code string
        
    Returns:
        Token diversity ratio [0, 1]
    """
    tokens = re.findall(r'\w+', code.lower())
    
    if not tokens:
        return 0.0
    
    unique_tokens = len(set(tokens))
    total_tokens = len(tokens)
    
    diversity = unique_tokens / total_tokens
    
    return round(diversity, 4)


def calculate_shannon_entropy(code: str) -> float:
    """
    Calculate Shannon entropy of code tokens.
    
    Measures information content and randomness.
    Higher entropy = more unpredictable/complex code.
    
    Args:
        code: Source code string
        
    Returns:
        Shannon entropy value
    """
    tokens = re.findall(r'\w+', code.lower())
    
    if not tokens:
        return 0.0
    
    # Count token frequencies
    token_counts = Counter(tokens)
    total = len(tokens)
    
    # Calculate entropy: H(X) = -Σ p(x) * log2(p(x))
    entropy = 0.0
    for count in token_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    
    return round(entropy, 4)


def calculate_identifier_entropy(code: str) -> float:
    """
    Calculate Shannon entropy of identifiers only (excludes keywords).
    
    Args:
        code: Source code string
        
    Returns:
        Identifier entropy value
    """
    tokens = re.findall(r'\w+', code.lower())
    identifiers = [t for t in tokens if t not in KEYWORDS and t.isalpha()]
    
    if not identifiers:
        return 0.0
    
    # Count identifier frequencies
    id_counts = Counter(identifiers)
    total = len(identifiers)
    
    # Calculate entropy
    entropy = 0.0
    for count in id_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    
    return round(entropy, 4)


# ====================================================================
# RATIO-BASED FEATURES
# ====================================================================

def calculate_ratios(metrics: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculate ratio-based features from existing metrics.
    
    Args:
        metrics: Dictionary with extracted metrics
        
    Returns:
        Dictionary of ratio features
    """
    ratios = {}
    
    # Comment to code ratio
    loc = metrics.get('loc', 1)
    comment_lines = metrics.get('comment_density', 0) * metrics.get('total_lines', 1)
    ratios['comment_code_ratio'] = round(comment_lines / loc if loc > 0 else 0, 4)
    
    # Identifier to keyword ratio
    id_count = metrics.get('identifier_count', 0)
    kw_count = metrics.get('keyword_count', 1)
    ratios['identifier_keyword_ratio'] = round(id_count / kw_count if kw_count > 0 else 0, 4)
    
    # Operator to operand ratio (Halstead-inspired)
    op_count = metrics.get('operator_count', 0)
    operand_count = id_count + metrics.get('numeric_count', 0)
    ratios['operator_operand_ratio'] = round(op_count / operand_count if operand_count > 0 else 0, 4)
    
    # Token density (tokens per line)
    tokens = metrics.get('num_tokens', 0)
    ratios['token_density'] = round(tokens / loc if loc > 0 else 0, 2)
    
    return ratios


# ====================================================================
# COMPREHENSIVE FEATURE EXTRACTION
# ====================================================================

def extract_all_features(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract all features from a single record.
    
    Args:
        record: Input record with code field
        
    Returns:
        Record enriched with all features
    """
    code = record.get('code', '')
    
    # Create copy of record
    enriched = {
        'id': record.get('id', ''),
        'language': record.get('language', ''),
        'label': record.get('label', 0),
        'source_dataset': record.get('source_dataset', '')
    }
    
    try:
        # 1. Basic code metrics
        code_metrics = extract_code_metrics(code)
        enriched.update(code_metrics)
        
        # 2. Lexical features
        lexical = extract_lexical_features(code)
        enriched.update(lexical)
        
        # 3. Complexity metrics
        enriched['cyclomatic_complexity'] = calculate_cyclomatic_complexity(code)
        enriched['nesting_depth'] = calculate_nesting_depth(code)
        enriched['ast_depth'] = calculate_ast_depth(code)
        enriched['conditional_count'] = calculate_conditional_count(code)
        enriched['loop_count'] = calculate_loop_count(code)
        
        # 4. Diversity and entropy
        enriched['token_diversity'] = calculate_token_diversity(code)
        enriched['shannon_entropy'] = calculate_shannon_entropy(code)
        enriched['identifier_entropy'] = calculate_identifier_entropy(code)
        
        # 5. Ratio-based features
        ratios = calculate_ratios(enriched)
        enriched.update(ratios)
        
    except Exception as e:
        logger.warning(f"Error extracting features for record {record.get('id')}: {e}")
        # Set default values for failed extraction
        enriched['extraction_error'] = True
    
    return enriched


# ====================================================================
# DATASET PROCESSING
# ====================================================================

def process_dataset_to_csv(
    input_path: str,
    output_csv_path: str,
    output_jsonl_path: Optional[str] = None,
    stats_path: Optional[str] = None,
    chunk_size: int = 10000
) -> Dict[str, Any]:
    """
    Process dataset and extract features to CSV format.
    
    Args:
        input_path: Input JSONL file (validated dataset)
        output_csv_path: Output CSV file with feature matrix
        output_jsonl_path: Optional JSONL output with features
        stats_path: Optional JSON file for statistics
        chunk_size: Chunk size for processing
        
    Returns:
        Statistics dictionary
    """
    logger.info("="*80)
    logger.info("PHASE 2.2 ENHANCED: ADVANCED FEATURE ENGINEERING")
    logger.info("="*80)
    logger.info(f"Input:        {input_path}")
    logger.info(f"Output CSV:   {output_csv_path}")
    if output_jsonl_path:
        logger.info(f"Output JSONL: {output_jsonl_path}")
    if stats_path:
        logger.info(f"Stats:        {stats_path}")
    logger.info(f"Chunk size:   {chunk_size:,}")
    logger.info("="*80)
    
    # Ensure output directories
    ensure_dir(Path(output_csv_path).parent)
    if output_jsonl_path:
        ensure_dir(Path(output_jsonl_path).parent)
    
    # Initialize tracking
    stats = {
        'start_time': datetime.now().isoformat(),
        'total_records': 0,
        'successful_extractions': 0,
        'failed_extractions': 0,
        'feature_stats': defaultdict(lambda: {
            'min': float('inf'),
            'max': float('-inf'),
            'sum': 0,
            'count': 0
        }),
        'dataset_counts': defaultdict(int),
        'language_counts': defaultdict(int)
    }
    
    # Open CSV writer
    csv_file = open(output_csv_path, 'w', newline='', encoding='utf-8')
    csv_writer = None
    fieldnames = None
    
    # Optional JSONL output
    jsonl_chunks = [] if output_jsonl_path else None
    
    # Process in chunks
    logger.info("Processing chunks...")
    for chunk_idx, chunk in enumerate(chunked_read_jsonl(input_path, chunk_size=chunk_size)):
        enriched_chunk = []
        
        for record in chunk:
            stats['total_records'] += 1
            
            # Track dataset and language distribution
            stats['dataset_counts'][record.get('source_dataset', 'unknown')] += 1
            stats['language_counts'][record.get('language', 'unknown')] += 1
            
            # Extract features
            enriched = extract_all_features(record)
            
            if enriched.get('extraction_error'):
                stats['failed_extractions'] += 1
            else:
                stats['successful_extractions'] += 1
            
            # Update feature statistics
            for field, value in enriched.items():
                if isinstance(value, (int, float)) and field not in ['id', 'label']:
                    stats['feature_stats'][field]['min'] = min(
                        stats['feature_stats'][field]['min'], value
                    )
                    stats['feature_stats'][field]['max'] = max(
                        stats['feature_stats'][field]['max'], value
                    )
                    stats['feature_stats'][field]['sum'] += value
                    stats['feature_stats'][field]['count'] += 1
            
            enriched_chunk.append(enriched)
            
            # Write to CSV
            if csv_writer is None:
                # Initialize CSV writer with fieldnames from first record
                fieldnames = list(enriched.keys())
                csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                csv_writer.writeheader()
            
            csv_writer.writerow(enriched)
        
        # Store for JSONL output
        if jsonl_chunks is not None:
            jsonl_chunks.append(enriched_chunk)
        
        # Progress
        if (chunk_idx + 1) % 10 == 0:
            logger.info(f"Processed {stats['total_records']:,} records "
                       f"({stats['successful_extractions']:,} successful)")
    
    # Close CSV file
    csv_file.close()
    
    # Write JSONL if requested
    if output_jsonl_path and jsonl_chunks:
        logger.info(f"Writing JSONL output...")
        chunked_write_jsonl(output_jsonl_path, iter(jsonl_chunks), show_progress=False)
    
    # Finalize statistics
    stats['end_time'] = datetime.now().isoformat()
    stats['success_rate'] = (
        stats['successful_extractions'] / stats['total_records']
        if stats['total_records'] > 0 else 0
    )
    
    # Calculate feature averages
    for field, field_stats in stats['feature_stats'].items():
        if field_stats['count'] > 0:
            field_stats['avg'] = field_stats['sum'] / field_stats['count']
            field_stats['avg'] = round(field_stats['avg'], 4)
            # Remove sum and count from output
            del field_stats['sum']
            del field_stats['count']
    
    # Convert defaultdicts to regular dicts
    stats['feature_stats'] = dict(stats['feature_stats'])
    stats['dataset_counts'] = dict(stats['dataset_counts'])
    stats['language_counts'] = dict(stats['language_counts'])
    
    # Write statistics
    if stats_path:
        logger.info(f"Writing statistics...")
        write_json(stats, stats_path, indent=2)
    
    # Print summary
    logger.info("="*80)
    logger.info("FEATURE ENGINEERING SUMMARY")
    logger.info("="*80)
    logger.info(f"Total records:        {stats['total_records']:,}")
    logger.info(f"Successful:           {stats['successful_extractions']:,}")
    logger.info(f"Failed:               {stats['failed_extractions']:,}")
    logger.info(f"Success rate:         {stats['success_rate']*100:.2f}%")
    logger.info(f"Features extracted:   {len(fieldnames) if fieldnames else 0}")
    logger.info("="*80)
    
    return stats


# ====================================================================
# CLI ENTRY POINT
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Phase 2.2: Advanced Feature Engineering"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Input JSONL file (validated dataset, auto-detected if not provided)"
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=None,
        help="Output CSV file with feature matrix (auto-detected if not provided)"
    )
    parser.add_argument(
        "--output-jsonl",
        type=str,
        default=None,
        help="Optional output JSONL file with features"
    )
    parser.add_argument(
        "--stats",
        type=str,
        default=None,
        help="Output statistics JSON file (auto-detected if not provided)"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=10000,
        help="Chunk size for processing"
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths using Kaggle-compatible helper
    if args.input:
        input_path = args.input
    else:
        unified_dir = get_output_path("unified")
        input_path = str(unified_dir / "validated.jsonl")
    
    if args.output_csv:
        output_csv_path = args.output_csv
    else:
        features_dir = get_output_path("features")
        output_csv_path = str(features_dir / "features_static.csv")
    
    if args.stats:
        stats_path = args.stats
    else:
        features_dir = get_output_path("features")
        stats_path = str(features_dir / "stats_features.json")
    
    logger.info(f"[INFO] Reading input from: {input_path}")
    logger.info(f"[INFO] Writing features to: {output_csv_path}")
    logger.info(f"[INFO] Writing statistics to: {stats_path}")
    
    process_dataset_to_csv(
        input_path=input_path,
        output_csv_path=output_csv_path,
        output_jsonl_path=args.output_jsonl,
        stats_path=stats_path,
        chunk_size=args.chunk_size
    )


def run(args=None):
    """Entry point for orchestrator."""
    if args is None:
        main()
    else:
        import sys
        original_argv = sys.argv.copy()
        try:
            sys.argv = ['feature_engineering_enhanced.py']
            if hasattr(args, 'input_file'):
                sys.argv.extend(['--input', args.input_file])
            if hasattr(args, 'output_csv'):
                sys.argv.extend(['--output-csv', args.output_csv])
            if hasattr(args, 'output_jsonl'):
                sys.argv.extend(['--output-jsonl', args.output_jsonl])
            if hasattr(args, 'stats_file'):
                sys.argv.extend(['--stats', args.stats_file])
            main()
        finally:
            sys.argv = original_argv


if __name__ == '__main__':
    main()
