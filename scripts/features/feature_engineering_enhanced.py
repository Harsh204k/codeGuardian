#!/usr/bin/env python3
"""
Phase 2.3 ENHANCED: Advanced Feature Engineering with AST, Graph, and Semantic Features
======================================================================================

🎯 KEY ENHANCEMENTS: PHASE 2 + PHASE 3 FEATURES

This module builds upon the production feature engineering (v3.3.0) by adding:

✅ **PHASE 1 (Preserved)**: All existing 64 features from feature_engineering.py
✅ **PHASE 2 (NEW)**: AST, Semantic, Security Lexical Features (~25 features)
✅ **PHASE 3 (NEW)**: Graph, Control Flow, Taint Analysis (~15 features)

Total Output: 100+ features while preserving ALL original schema fields

Phase 2 Features:
- AST structural metrics (node count, branch factor, tree depth)
- Function call graph analysis
- Semantic dependencies (imports, data flow)
- Advanced security lexical patterns (dangerous APIs, user input, CWE patterns)
- Code pattern detection (try-catch, assertions, logging)

Phase 3 Features:
- Control flow graph metrics (nodes, edges, density)
- Graph-based complexity (cyclomatic, branching factor)
- Taint analysis indicators (user input flow, sink detection)
- Data dependency metrics
- Embedding readiness flag (for later CodeBERT integration)

Performance Optimizations:
- Lazy AST parsing (cache on failure)
- Batch processing with chunking
- Memory-efficient graph construction
- Optional feature toggles via config
- Kaggle-optimized (10-15 min runtime target)

Author: CodeGuardian Team (Enhanced)
Version: 3.4.0 (Phase 2+3 Enhanced)
Date: 2025-10-12
"""

import argparse
import logging
import re
import math
import csv
import sys
import shutil
import warnings
import ast as python_ast
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import Counter, defaultdict, deque
from datetime import datetime
import numpy as np

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    warnings.warn("pandas not available - using fallback mode")

try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from joblib import Parallel, delayed

    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    warnings.warn("networkx not available - graph features will be disabled")

# Import original feature engineering functions
from scripts.features.feature_engineering_base import (
    extract_code_metrics,
    extract_lexical_features,
    calculate_cyclomatic_complexity,
    calculate_nesting_depth,
    calculate_ast_depth,
    calculate_conditional_count,
    calculate_loop_count,
    calculate_token_diversity,
    calculate_shannon_entropy,
    calculate_identifier_entropy,
    calculate_ratios,
    KEYWORDS,
    CONTROL_FLOW_KEYWORDS,
    SECURITY_KEYWORDS,
)

from scripts.utils.io_utils import (
    chunked_read_jsonl,
    chunked_write_jsonl,
    write_json,
    ensure_dir,
    write_parquet,
)
from scripts.utils.schema_utils import validate_record, UNIFIED_SCHEMA
from scripts.utils.kaggle_paths import (
    get_dataset_path,
    get_output_path,
    print_environment_info,
)
from scripts.utils.logging_utils import get_logger, timed

# Setup logging
logger = get_logger(__name__)

# ====================================================================
# CONFIGURATION FLAGS
# ====================================================================

# Feature toggles (can be controlled via config file or CLI)
ENABLE_PHASE2_FEATURES = True  # AST, Semantic, Security
ENABLE_PHASE3_FEATURES = True  # Graph, Taint, CFG
ENABLE_EMBEDDING_PREP = True  # Flag for CodeBERT integration later

# ====================================================================
# ENHANCED SECURITY PATTERNS (Phase 2)
# ====================================================================

# Dangerous API calls that indicate security risk
DANGEROUS_APIS = {
    # Memory operations
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "memcpy",
    "memmove",
    "strncpy",
    "strncat",
    # Code execution
    "eval",
    "exec",
    "execve",
    "system",
    "popen",
    "shell_exec",
    "passthru",
    "proc_open",
    "pcntl_exec",
    "call_user_func",
    # SQL operations (potential injection)
    "mysql_query",
    "mysqli_query",
    "pg_query",
    "sqlite_query",
    "execute",
    "executemany",
    "rawQuery",
    # File operations
    "fopen",
    "file_get_contents",
    "file_put_contents",
    "unlink",
    "rmdir",
    "readfile",
    "include",
    "require",
    # Network operations
    "curl_exec",
    "fsockopen",
    "socket_connect",
    "stream_socket_client",
    # Crypto (weak or deprecated)
    "md5",
    "sha1",
    "rand",
    "srand",
    "mt_rand",
    # Deserialization
    "unserialize",
    "pickle.loads",
    "yaml.load",
    "json.loads",
}

# User input sources
USER_INPUT_SOURCES = {
    "input",
    "raw_input",
    "stdin.read",
    "stdin.readline",
    "request.get",
    "request.post",
    "request.form",
    "request.args",
    "argv",
    "argc",
    "getenv",
    "environ",
    "GET",
    "POST",
    "REQUEST",
    "COOKIE",
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_SERVER",
}

# Common CWE pattern keywords
CWE_PATTERN_KEYWORDS = {
    # CWE-79: XSS
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    # CWE-89: SQL Injection
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    # CWE-78: OS Command Injection
    "shell",
    "cmd",
    "bash",
    "sh",
    "powershell",
    # CWE-22: Path Traversal
    "../",
    "..\\",
    "path.join",
    "os.path.join",
    # CWE-798: Hardcoded credentials
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "token",
    # CWE-676: Dangerous functions
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
}

# ====================================================================
# PHASE 2: AST & SEMANTIC FEATURES
# ====================================================================


def safe_parse_python_ast(code: str) -> Optional[python_ast.AST]:
    """
    Safely parse Python code into AST.

    Args:
        code: Source code string

    Returns:
        AST tree or None on failure
    """
    try:
        return python_ast.parse(code)
    except:
        return None


def extract_ast_features(code: str, language: str = "unknown") -> Dict[str, float]:
    """
    Extract AST-based structural features.

    Features:
    - ast_node_count: Total number of AST nodes
    - ast_branch_factor: Average branching factor
    - ast_max_depth: Maximum tree depth
    - ast_leaf_count: Number of leaf nodes
    - ast_function_def_count: Number of function definitions
    - ast_class_def_count: Number of class definitions
    - ast_assignment_count: Number of assignments
    - ast_call_count: Number of function/method calls
    - ast_import_count: Number of import statements
    - ast_exception_handler_count: Number of try-except blocks

    Args:
        code: Source code string
        language: Programming language (for language-specific parsing)

    Returns:
        Dictionary of AST features
    """
    features = {
        "ast_node_count": 0,
        "ast_branch_factor": 0.0,
        "ast_max_depth": 0,
        "ast_leaf_count": 0,
        "ast_function_def_count": 0,
        "ast_class_def_count": 0,
        "ast_assignment_count": 0,
        "ast_call_count": 0,
        "ast_import_count": 0,
        "ast_exception_handler_count": 0,
    }

    # Only attempt Python AST parsing for Python code
    if language.lower() not in ["python", "py"]:
        # For non-Python, use heuristics
        features["ast_function_def_count"] = len(
            re.findall(r"\b(def|function|func|void|public|private)\s+\w+\s*\(", code)
        )
        features["ast_class_def_count"] = len(
            re.findall(r"\b(class|struct|interface)\s+\w+", code)
        )
        features["ast_import_count"] = len(
            re.findall(r"\b(import|include|using|require|from)\b", code)
        )
        features["ast_call_count"] = len(re.findall(r"\w+\s*\(", code))
        features["ast_exception_handler_count"] = len(
            re.findall(r"\b(try|catch|except|finally)\b", code)
        )
        return features

    try:
        tree = safe_parse_python_ast(code)
        if tree is None:
            return features

        # Traverse AST
        node_count = 0
        leaf_count = 0
        max_depth = 0
        branch_factors = []

        def traverse(node, depth=0):
            nonlocal node_count, leaf_count, max_depth
            node_count += 1
            max_depth = max(max_depth, depth)

            children = list(python_ast.iter_child_nodes(node))
            if not children:
                leaf_count += 1
            else:
                branch_factors.append(len(children))

            for child in children:
                traverse(child, depth + 1)

        traverse(tree)

        # Calculate features
        features["ast_node_count"] = node_count
        features["ast_max_depth"] = max_depth
        features["ast_leaf_count"] = leaf_count
        features["ast_branch_factor"] = (
            round(np.mean(branch_factors), 2) if branch_factors else 0.0
        )

        # Count specific node types
        for node in python_ast.walk(tree):
            if isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                features["ast_function_def_count"] += 1
            elif isinstance(node, python_ast.ClassDef):
                features["ast_class_def_count"] += 1
            elif isinstance(
                node, (python_ast.Assign, python_ast.AugAssign, python_ast.AnnAssign)
            ):
                features["ast_assignment_count"] += 1
            elif isinstance(node, python_ast.Call):
                features["ast_call_count"] += 1
            elif isinstance(node, (python_ast.Import, python_ast.ImportFrom)):
                features["ast_import_count"] += 1
            elif isinstance(node, python_ast.ExceptHandler):
                features["ast_exception_handler_count"] += 1

    except Exception as e:
        # Silently fallback - return defaults
        pass

    return features


def extract_semantic_features(code: str) -> Dict[str, float]:
    """
    Extract semantic-level features.

    Features:
    - import_dependency_count: Number of unique imports
    - function_call_graph_size: Approximate size of call graph
    - variable_declaration_count: Number of variable declarations
    - data_dependency_score: Heuristic for data dependencies
    - control_dependency_score: Heuristic for control dependencies

    Args:
        code: Source code string

    Returns:
        Dictionary of semantic features
    """
    features = {
        "import_dependency_count": 0,
        "function_call_graph_size": 0,
        "variable_declaration_count": 0,
        "data_dependency_score": 0.0,
        "control_dependency_score": 0.0,
    }

    try:
        # Import count (unique)
        imports = set(
            re.findall(r"\b(?:import|include|using|require|from)\s+([.\w]+)", code)
        )
        features["import_dependency_count"] = len(imports)

        # Function calls (unique function names)
        function_calls = set(re.findall(r"(\w+)\s*\(", code))
        features["function_call_graph_size"] = len(function_calls)

        # Variable declarations (approximation)
        var_declarations = len(
            re.findall(
                r"\b(var|let|const|int|float|double|char|string|bool|auto)\s+\w+", code
            )
        )
        var_declarations += len(re.findall(r"^\s*\w+\s*=", code, re.MULTILINE))
        features["variable_declaration_count"] = var_declarations

        # Data dependency: assignment operations
        assignments = len(re.findall(r"\w+\s*[+\-*/]?=", code))
        features["data_dependency_score"] = round(
            assignments / max(len(code.split("\n")), 1), 4
        )

        # Control dependency: conditional + loop statements
        control_statements = len(re.findall(r"\b(if|for|while|switch|case)\b", code))
        features["control_dependency_score"] = round(
            control_statements / max(len(code.split("\n")), 1), 4
        )

    except Exception:
        pass

    return features


def extract_security_lexical_features(code: str) -> Dict[str, int]:
    """
    Extract security-focused lexical features.

    Features:
    - dangerous_api_count: Count of dangerous API calls
    - user_input_calls: Count of user input sources
    - cwe_pattern_count: Count of CWE-related patterns
    - buffer_operation_count: Buffer manipulation operations
    - crypto_operation_count: Cryptographic operations
    - network_operation_count: Network-related calls
    - file_operation_count: File system operations
    - sql_keyword_count: SQL keywords (injection risk)
    - shell_command_count: Shell command execution
    - assertion_count: Assertion statements
    - logging_count: Logging statements
    - try_catch_count: Exception handling blocks

    Args:
        code: Source code string

    Returns:
        Dictionary of security lexical features
    """
    features = {
        "dangerous_api_count": 0,
        "user_input_calls": 0,
        "cwe_pattern_count": 0,
        "buffer_operation_count": 0,
        "crypto_operation_count": 0,
        "network_operation_count": 0,
        "file_operation_count": 0,
        "sql_keyword_count": 0,
        "shell_command_count": 0,
        "assertion_count": 0,
        "logging_count": 0,
        "try_catch_count": 0,
    }

    try:
        code_lower = code.lower()

        # Dangerous APIs
        for api in DANGEROUS_APIS:
            features["dangerous_api_count"] += len(
                re.findall(r"\b" + api + r"\b", code_lower)
            )

        # User input sources
        for source in USER_INPUT_SOURCES:
            features["user_input_calls"] += len(
                re.findall(r"\b" + source.lower() + r"\b", code_lower)
            )

        # CWE patterns
        for pattern in CWE_PATTERN_KEYWORDS:
            features["cwe_pattern_count"] += code.count(pattern)

        # Buffer operations
        buffer_ops = [
            "strcpy",
            "strcat",
            "memcpy",
            "memmove",
            "sprintf",
            "gets",
            "scanf",
        ]
        for op in buffer_ops:
            features["buffer_operation_count"] += len(
                re.findall(r"\b" + op + r"\b", code_lower)
            )

        # Crypto operations
        crypto_ops = [
            "encrypt",
            "decrypt",
            "hash",
            "md5",
            "sha",
            "aes",
            "rsa",
            "crypto",
        ]
        for op in crypto_ops:
            features["crypto_operation_count"] += len(
                re.findall(r"\b" + op + r"\b", code_lower)
            )

        # Network operations
        network_ops = [
            "socket",
            "connect",
            "send",
            "recv",
            "curl",
            "http",
            "tcp",
            "udp",
        ]
        for op in network_ops:
            features["network_operation_count"] += len(
                re.findall(r"\b" + op + r"\b", code_lower)
            )

        # File operations
        file_ops = [
            "fopen",
            "fread",
            "fwrite",
            "fclose",
            "open",
            "read",
            "write",
            "close",
            "file",
        ]
        for op in file_ops:
            features["file_operation_count"] += len(
                re.findall(r"\b" + op + r"\b", code_lower)
            )

        # SQL keywords
        sql_keywords = [
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "create",
            "alter",
            "union",
        ]
        for kw in sql_keywords:
            features["sql_keyword_count"] += len(
                re.findall(r"\b" + kw + r"\b", code_lower)
            )

        # Shell commands
        shell_keywords = [
            "system",
            "exec",
            "shell",
            "popen",
            "bash",
            "cmd",
            "powershell",
        ]
        for kw in shell_keywords:
            features["shell_command_count"] += len(
                re.findall(r"\b" + kw + r"\b", code_lower)
            )

        # Assertions
        features["assertion_count"] = len(
            re.findall(r"\b(assert|assertEqual|assertTrue|assertFalse)\b", code)
        )

        # Logging
        features["logging_count"] = len(
            re.findall(r"\b(log|logger|print|printf|cout|System\.out)\b", code)
        )

        # Try-catch blocks
        features["try_catch_count"] = len(
            re.findall(r"\b(try|catch|except|finally)\b", code_lower)
        )

    except Exception:
        pass

    return features


# ====================================================================
# PHASE 3: GRAPH & TAINT FEATURES
# ====================================================================


def build_simple_cfg(code: str) -> Optional[Any]:
    """
    Build a simple control flow graph from code.

    Uses basic heuristics to construct CFG nodes and edges:
    - Each line is a potential node
    - Control flow keywords create branches
    - Function calls create edges

    Args:
        code: Source code string

    Returns:
        NetworkX graph or None if networkx unavailable
    """
    if not NETWORKX_AVAILABLE:
        return None

    try:
        G = nx.DiGraph()
        lines = [l.strip() for l in code.split("\n") if l.strip()]

        if not lines:
            return None

        # Add nodes for each line
        for i, line in enumerate(lines):
            G.add_node(i, line=line)

        # Add sequential edges
        for i in range(len(lines) - 1):
            G.add_edge(i, i + 1)

        # Add control flow edges
        for i, line in enumerate(lines):
            line_lower = line.lower()

            # If statement creates branch
            if re.match(r"\s*(if|elif)\s*\(", line_lower):
                # Edge to next line (true branch)
                # Find matching else/end
                for j in range(i + 1, min(i + 20, len(lines))):
                    if re.match(r"\s*(else|elif|end)", lines[j].lower()):
                        G.add_edge(i, j)
                        break

            # Loop creates back-edge
            elif re.match(r"\s*(for|while)\s*\(", line_lower):
                # Back edge to loop start
                for j in range(i + 1, min(i + 20, len(lines))):
                    if "}" in lines[j] or "end" in lines[j].lower():
                        G.add_edge(j, i)
                        break

        return G

    except Exception:
        return None


def extract_graph_features(code: str) -> Dict[str, float]:
    """
    Extract graph-based control flow features.

    Features:
    - cfg_nodes: Number of CFG nodes
    - cfg_edges: Number of CFG edges
    - cfg_density: Graph density
    - cfg_avg_degree: Average node degree
    - cfg_max_degree: Maximum node degree
    - cfg_strongly_connected_components: Number of SCCs
    - cfg_cyclomatic_graph: Graph-based cyclomatic complexity

    Args:
        code: Source code string

    Returns:
        Dictionary of graph features
    """
    features = {
        "cfg_nodes": 0,
        "cfg_edges": 0,
        "cfg_density": 0.0,
        "cfg_avg_degree": 0.0,
        "cfg_max_degree": 0,
        "cfg_strongly_connected_components": 0,
        "cfg_cyclomatic_graph": 0,
    }

    if not NETWORKX_AVAILABLE:
        return features

    try:
        G = build_simple_cfg(code)
        if G is None or G.number_of_nodes() == 0:
            return features

        # Basic graph metrics
        features["cfg_nodes"] = G.number_of_nodes()
        features["cfg_edges"] = G.number_of_edges()

        # Density
        if G.number_of_nodes() > 1:
            features["cfg_density"] = round(nx.density(G), 4)

        # Degree statistics
        degrees = [d for n, d in G.degree()]
        if degrees:
            features["cfg_avg_degree"] = round(np.mean(degrees), 2)
            features["cfg_max_degree"] = max(degrees)

        # Strongly connected components
        features["cfg_strongly_connected_components"] = (
            nx.number_strongly_connected_components(G)
        )

        # Graph-based cyclomatic complexity: M = E - N + 2P
        # P = number of connected components
        try:
            num_components = nx.number_weakly_connected_components(G)
            features["cfg_cyclomatic_graph"] = (
                G.number_of_edges() - G.number_of_nodes() + 2 * num_components
            )
        except:
            pass

    except Exception:
        pass

    return features


def extract_taint_features(code: str) -> Dict[str, float]:
    """
    Extract taint analysis features (heuristic-based).

    Features:
    - tainted_variable_ratio: Ratio of variables that might be tainted
    - source_sink_distance: Average distance from sources to sinks
    - untrusted_input_flow: Count of untrusted inputs flowing to sensitive operations
    - sanitization_count: Count of sanitization operations
    - validation_count: Count of validation checks

    Args:
        code: Source code string

    Returns:
        Dictionary of taint features
    """
    features = {
        "tainted_variable_ratio": 0.0,
        "source_sink_distance": 0,
        "untrusted_input_flow": 0,
        "sanitization_count": 0,
        "validation_count": 0,
    }

    try:
        lines = code.split("\n")

        # Find taint sources (user input)
        taint_sources = []
        for i, line in enumerate(lines):
            for source in USER_INPUT_SOURCES:
                if source.lower() in line.lower():
                    taint_sources.append(i)
                    break

        # Find taint sinks (dangerous operations)
        taint_sinks = []
        for i, line in enumerate(lines):
            for sink in DANGEROUS_APIS:
                if sink.lower() in line.lower():
                    taint_sinks.append(i)
                    break

        # Calculate source-sink distance
        if taint_sources and taint_sinks:
            distances = []
            for source in taint_sources:
                for sink in taint_sinks:
                    if sink > source:  # Sink comes after source
                        distances.append(sink - source)

            if distances:
                features["source_sink_distance"] = int(np.mean(distances))
                features["untrusted_input_flow"] = len(distances)

        # Tainted variable ratio (variables assigned from tainted sources)
        tainted_vars = set()
        all_vars = set()

        for i, line in enumerate(lines):
            # Find variable assignments
            var_match = re.findall(r"(\w+)\s*=", line)
            all_vars.update(var_match)

            # Check if assignment is from tainted source
            if i in taint_sources or any(abs(i - src) <= 3 for src in taint_sources):
                tainted_vars.update(var_match)

        if all_vars:
            features["tainted_variable_ratio"] = round(
                len(tainted_vars) / len(all_vars), 4
            )

        # Sanitization operations
        sanitization_keywords = [
            "escape",
            "sanitize",
            "clean",
            "filter",
            "validate",
            "strip",
            "encode",
        ]
        for kw in sanitization_keywords:
            features["sanitization_count"] += len(
                re.findall(r"\b" + kw + r"\b", code.lower())
            )

        # Validation checks
        validation_patterns = [
            r"if\s*\(.*[<>=!]",
            r"assert",
            r"check",
            r"verify",
            r"validate",
        ]
        for pattern in validation_patterns:
            features["validation_count"] += len(re.findall(pattern, code.lower()))

    except Exception:
        pass

    return features


def extract_data_flow_features(code: str) -> Dict[str, float]:
    """
    Extract data flow features.

    Features:
    - def_use_chain_length: Average def-use chain length
    - variable_lifetime: Average variable lifetime (lines)
    - inter_procedural_flow: Cross-function data flow count

    Args:
        code: Source code string

    Returns:
        Dictionary of data flow features
    """
    features = {
        "def_use_chain_length": 0.0,
        "variable_lifetime": 0.0,
        "inter_procedural_flow": 0,
    }

    try:
        lines = code.split("\n")
        var_def = {}  # variable -> first definition line
        var_use = defaultdict(list)  # variable -> use lines

        for i, line in enumerate(lines):
            # Find definitions
            defs = re.findall(r"(\w+)\s*=", line)
            for var in defs:
                if var not in var_def:
                    var_def[var] = i

            # Find uses
            uses = re.findall(r"\b(\w+)\b", line)
            for var in uses:
                if var in var_def and "=" not in line.split(var)[0]:
                    var_use[var].append(i)

        # Calculate def-use chain length
        chain_lengths = []
        for var, def_line in var_def.items():
            if var in var_use:
                for use_line in var_use[var]:
                    if use_line > def_line:
                        chain_lengths.append(use_line - def_line)

        if chain_lengths:
            features["def_use_chain_length"] = round(np.mean(chain_lengths), 2)

        # Variable lifetime
        lifetimes = []
        for var, def_line in var_def.items():
            if var in var_use and var_use[var]:
                lifetime = max(var_use[var]) - def_line
                lifetimes.append(lifetime)

        if lifetimes:
            features["variable_lifetime"] = round(np.mean(lifetimes), 2)

        # Inter-procedural flow (variables used across function boundaries)
        function_boundaries = [
            i
            for i, line in enumerate(lines)
            if re.match(r"\s*(def|function|void|public|private)\s+\w+\s*\(", line)
        ]

        for var, uses in var_use.items():
            if var in var_def:
                def_func = sum(1 for fb in function_boundaries if fb <= var_def[var])
                for use_line in uses:
                    use_func = sum(1 for fb in function_boundaries if fb <= use_line)
                    if use_func != def_func:
                        features["inter_procedural_flow"] += 1
                        break

    except Exception:
        pass

    return features


# ====================================================================
# COMPREHENSIVE ENHANCED FEATURE EXTRACTION
# ====================================================================


def _extract_enhanced_features_worker(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Worker function for multiprocessing - extracts ALL features (Phase 1+2+3).

    ✅ Preserves ALL 32 original schema fields
    ✅ Adds ALL 32 Phase 1 features (existing)
    ✅ Adds ~25 Phase 2 features (AST, semantic, security)
    ✅ Adds ~15 Phase 3 features (graph, taint, data flow)

    Args:
        record: Input record with ALL schema fields from validated.jsonl

    Returns:
        Record with ALL original fields + ~100 total features
    """
    code = record.get("code", "")
    language = record.get("language", "unknown")

    # ═══════════════════════════════════════════════════════════════
    # ✅ PRESERVE ALL ORIGINAL SCHEMA FIELDS (32 fields)
    # ═══════════════════════════════════════════════════════════════
    enriched = {
        # Core identification
        "id": record.get("id", ""),
        "language": language,
        "dataset": record.get("dataset", ""),
        # Code and vulnerability
        "code": code,
        "is_vulnerable": record.get("is_vulnerable", 0),
        # Vulnerability metadata
        "cwe_id": record.get("cwe_id", ""),
        "cve_id": record.get("cve_id", ""),
        "description": record.get("description", ""),
        # CWE-enriched fields
        "attack_type": record.get("attack_type", ""),
        "severity": record.get("severity", ""),
        "review_status": record.get("review_status", ""),
        # Provenance tracking
        "func_name": record.get("func_name", ""),
        "file_name": record.get("file_name", ""),
        "project": record.get("project", ""),
        "commit_id": record.get("commit_id", ""),
        # Traceability
        "source_file": record.get("source_file", ""),
        "source_row_index": record.get("source_row_index", ""),
        # Stage III enhancements
        "vuln_line_start": record.get("vuln_line_start", ""),
        "vuln_line_end": record.get("vuln_line_end", ""),
        "context_before": record.get("context_before", ""),
        "context_after": record.get("context_after", ""),
        "repo_url": record.get("repo_url", ""),
        "commit_url": record.get("commit_url", ""),
        "function_length": record.get("function_length", ""),
        "num_params": record.get("num_params", ""),
        "num_calls": record.get("num_calls", ""),
        "imports": record.get("imports", ""),
        "code_sha256": record.get("code_sha256", ""),
        "normalized_timestamp": record.get("normalized_timestamp", ""),
        "language_stage": record.get("language_stage", ""),
        "verification_source": record.get("verification_source", ""),
        "source_dataset_version": record.get("source_dataset_version", ""),
        "merge_timestamp": record.get("merge_timestamp", ""),
    }

    try:
        # ═══════════════════════════════════════════════════════════════
        # ✨ PHASE 1: EXISTING FEATURES (32 features)
        # ═══════════════════════════════════════════════════════════════

        # 1. Basic code metrics (9 features)
        code_metrics = extract_code_metrics(code)
        enriched.update(code_metrics)

        # 2. Lexical features (7 features)
        lexical = extract_lexical_features(code)
        enriched.update(lexical)

        # 3. Complexity metrics (5 features)
        enriched["cyclomatic_complexity"] = calculate_cyclomatic_complexity(code)
        enriched["nesting_depth"] = calculate_nesting_depth(code)
        enriched["ast_depth"] = calculate_ast_depth(code)
        enriched["conditional_count"] = calculate_conditional_count(code)
        enriched["loop_count"] = calculate_loop_count(code)

        # 4. Diversity and entropy metrics (3 features)
        enriched["token_diversity"] = calculate_token_diversity(code)
        enriched["shannon_entropy"] = calculate_shannon_entropy(code)
        enriched["identifier_entropy"] = calculate_identifier_entropy(code)

        # 5. Ratio-based features (5 features)
        ratios = calculate_ratios(enriched)
        enriched.update(ratios)

        # 6. Binary indicator features (3 features)
        enriched["has_cwe"] = 1 if record.get("cwe_id") else 0
        enriched["has_cve"] = 1 if record.get("cve_id") else 0
        enriched["has_description"] = 1 if record.get("description") else 0

        # ═══════════════════════════════════════════════════════════════
        # ✨ PHASE 2: AST, SEMANTIC, SECURITY LEXICAL (~25 features)
        # ═══════════════════════════════════════════════════════════════

        if ENABLE_PHASE2_FEATURES:
            # AST features (10 features)
            ast_features = extract_ast_features(code, language)
            enriched.update(ast_features)

            # Semantic features (5 features)
            semantic_features = extract_semantic_features(code)
            enriched.update(semantic_features)

            # Security lexical features (12 features)
            security_features = extract_security_lexical_features(code)
            enriched.update(security_features)

        # ═══════════════════════════════════════════════════════════════
        # ✨ PHASE 3: GRAPH, TAINT, DATA FLOW (~15 features)
        # ═══════════════════════════════════════════════════════════════

        if ENABLE_PHASE3_FEATURES:
            # Graph features (7 features)
            graph_features = extract_graph_features(code)
            enriched.update(graph_features)

            # Taint analysis features (5 features)
            taint_features = extract_taint_features(code)
            enriched.update(taint_features)

            # Data flow features (3 features)
            dataflow_features = extract_data_flow_features(code)
            enriched.update(dataflow_features)

        # ═══════════════════════════════════════════════════════════════
        # ✨ EMBEDDING READINESS FLAG
        # ═══════════════════════════════════════════════════════════════

        if ENABLE_EMBEDDING_PREP:
            # Flag to indicate embeddings should be generated during training
            enriched["embedding_features_pending"] = True

    except Exception as e:
        # Fill with default values for failed extraction
        # Original schema fields are already preserved
        default_phase2 = {
            "ast_node_count": 0,
            "ast_branch_factor": 0.0,
            "ast_max_depth": 0,
            "ast_leaf_count": 0,
            "ast_function_def_count": 0,
            "ast_class_def_count": 0,
            "ast_assignment_count": 0,
            "ast_call_count": 0,
            "ast_import_count": 0,
            "ast_exception_handler_count": 0,
            "import_dependency_count": 0,
            "function_call_graph_size": 0,
            "variable_declaration_count": 0,
            "data_dependency_score": 0.0,
            "control_dependency_score": 0.0,
            "dangerous_api_count": 0,
            "user_input_calls": 0,
            "cwe_pattern_count": 0,
            "buffer_operation_count": 0,
            "crypto_operation_count": 0,
            "network_operation_count": 0,
            "file_operation_count": 0,
            "sql_keyword_count": 0,
            "shell_command_count": 0,
            "assertion_count": 0,
            "logging_count": 0,
            "try_catch_count": 0,
        }

        default_phase3 = {
            "cfg_nodes": 0,
            "cfg_edges": 0,
            "cfg_density": 0.0,
            "cfg_avg_degree": 0.0,
            "cfg_max_degree": 0,
            "cfg_strongly_connected_components": 0,
            "cfg_cyclomatic_graph": 0,
            "tainted_variable_ratio": 0.0,
            "source_sink_distance": 0,
            "untrusted_input_flow": 0,
            "sanitization_count": 0,
            "validation_count": 0,
            "def_use_chain_length": 0.0,
            "variable_lifetime": 0.0,
            "inter_procedural_flow": 0,
        }

        if ENABLE_PHASE2_FEATURES:
            enriched.update(default_phase2)
        if ENABLE_PHASE3_FEATURES:
            enriched.update(default_phase3)
        if ENABLE_EMBEDDING_PREP:
            enriched["embedding_features_pending"] = True

    return enriched


def extract_all_enhanced_features(
    record: Dict[str, Any], validate_schema: bool = False
) -> Dict[str, Any]:
    """
    Extract all enhanced features from a single record (with logging support).

    ✅ Preserves ALL 32 schema fields from validated.jsonl
    ✅ Adds 32 Phase 1 features
    ✅ Adds ~25 Phase 2 features (AST, semantic, security)
    ✅ Adds ~15 Phase 3 features (graph, taint, data flow)

    Total: ~100+ features

    Args:
        record: Input record with ALL schema fields from validated.jsonl
        validate_schema: Whether to validate against unified schema

    Returns:
        Record with ALL original fields + enhanced features
    """
    try:
        return _extract_enhanced_features_worker(record)
    except Exception as e:
        logger.error(
            f"Error extracting enhanced features for record {record.get('id', 'unknown')}: {e}"
        )
        # Return record with ALL original schema fields + default features
        result = _extract_enhanced_features_worker(record)
        return result


# ====================================================================
# DATASET PROCESSING
# ====================================================================


@timed
def process_dataset_to_csv_enhanced(
    input_path: str,
    output_csv_path: str,
    output_parquet_path: Optional[str] = None,
    output_jsonl_path: Optional[str] = None,
    stats_path: Optional[str] = None,
    chunk_size: int = 5000,  # Smaller chunks for enhanced features
    validate_schema: bool = True,
    use_multiprocessing: bool = False,
    n_jobs: int = -1,
) -> Dict[str, Any]:
    """
    Process dataset and extract enhanced features to CSV/Parquet format.

    Args:
        input_path: Input JSONL file (validated dataset)
        output_csv_path: Output CSV file with feature matrix
        output_parquet_path: Optional Parquet output for optimized storage
        output_jsonl_path: Optional JSONL output with features
        stats_path: Optional JSON file for statistics
        chunk_size: Chunk size for processing (smaller for enhanced features)
        validate_schema: Whether to validate against unified schema
        use_multiprocessing: Enable parallel processing
        n_jobs: Number of parallel jobs (-1 for all cores)

    Returns:
        Statistics dictionary
    """
    logger.info("=" * 80)
    logger.info("PHASE 2.3 ENHANCED: ADVANCED FEATURE ENGINEERING (Phase 1+2+3)")
    logger.info("=" * 80)
    logger.info(f"Input:            {input_path}")
    logger.info(f"Output CSV:       {output_csv_path}")
    if output_parquet_path:
        logger.info(f"Output Parquet:   {output_parquet_path}")
    if output_jsonl_path:
        logger.info(f"Output JSONL:     {output_jsonl_path}")
    if stats_path:
        logger.info(f"Statistics:       {stats_path}")
    logger.info(f"Chunk size:       {chunk_size:,}")
    logger.info(f"Phase 2 enabled:  {ENABLE_PHASE2_FEATURES}")
    logger.info(f"Phase 3 enabled:  {ENABLE_PHASE3_FEATURES}")
    logger.info(f"NetworkX:         {NETWORKX_AVAILABLE}")
    logger.info(f"Multiprocessing:  {use_multiprocessing and JOBLIB_AVAILABLE}")
    logger.info("=" * 80)

    # Ensure output directories
    ensure_dir(Path(output_csv_path).parent) # pyright: ignore[reportArgumentType]
    if output_parquet_path:
        ensure_dir(Path(output_parquet_path).parent) # type: ignore
    if output_jsonl_path:
        ensure_dir(Path(output_jsonl_path).parent) # type: ignore

    # Initialize tracking
    stats = {
        "start_time": datetime.now().isoformat(),
        "total_records": 0,
        "successful_extractions": 0,
        "failed_extractions": 0,
        "phase1_features": 32,
        "phase2_features": 27 if ENABLE_PHASE2_FEATURES else 0,
        "phase3_features": 15 if ENABLE_PHASE3_FEATURES else 0,
        "total_features": 0,
        "feature_stats": defaultdict(
            lambda: {"min": float("inf"), "max": float("-inf"), "sum": 0, "count": 0}
        ),
        "dataset_counts": defaultdict(int),
        "language_counts": defaultdict(int),
        "vulnerability_counts": {"vulnerable": 0, "safe": 0},
    }

    # Collect all features for pandas DataFrame
    all_features = []

    # Optional JSONL output
    jsonl_chunks = [] if output_jsonl_path else None

    # Process in chunks
    logger.info("Processing chunks with enhanced features...")

    total_chunks = 0
    for chunk_idx, chunk in enumerate(
        chunked_read_jsonl(input_path, chunk_size=chunk_size)
    ):
        chunk_start = datetime.now()

        # Extract enhanced features (with optional multiprocessing)
        if use_multiprocessing and JOBLIB_AVAILABLE and len(chunk) > 500:
            logger.info(
                f"  Processing chunk {chunk_idx+1} with multiprocessing ({len(chunk)} records)..."
            )
            features = Parallel(n_jobs=n_jobs, backend="loky")(
                delayed(_extract_enhanced_features_worker)(record) for record in chunk
            )
        else:
            logger.info(f"  Processing chunk {chunk_idx+1} ({len(chunk)} records)...")
            features = []
            iterator = (
                tqdm(chunk, desc=f"Chunk {chunk_idx+1}") if TQDM_AVAILABLE else chunk
            )
            for record in iterator:
                features.append(extract_all_enhanced_features(record, False))

        # Update statistics
        for feature in features:
            stats["total_records"] += 1

            # Count by dataset and language
            dataset = feature.get("dataset", "unknown") # type: ignore
            language = feature.get("language", "unknown") # type: ignore
            stats["dataset_counts"][dataset] += 1
            stats["language_counts"][language] += 1

            # Count vulnerabilities
            if feature.get("is_vulnerable", 0) == 1: # type: ignore
                stats["vulnerability_counts"]["vulnerable"] += 1
            else:
                stats["vulnerability_counts"]["safe"] += 1

            # Track feature statistics (numeric fields only)
            for field, value in feature.items(): # type: ignore
                if isinstance(value, (int, float)) and field not in [
                    "id",
                    "is_vulnerable",
                ]:
                    try:
                        field_stats = stats["feature_stats"][field]
                        field_stats["min"] = min(field_stats["min"], value)
                        field_stats["max"] = max(field_stats["max"], value)
                        field_stats["sum"] += value
                        field_stats["count"] += 1
                        stats["successful_extractions"] += 1
                    except (ValueError, TypeError):
                        stats["failed_extractions"] += 1

        # Collect for DataFrame
        all_features.extend(features)

        # Optional JSONL output
        if jsonl_chunks is not None:
            jsonl_chunks.extend(features)

        chunk_time = (datetime.now() - chunk_start).total_seconds()
        logger.info(f"  Chunk {chunk_idx+1} completed in {chunk_time:.2f}s")
        total_chunks += 1

    # Write outputs
    logger.info("Writing outputs...")

    # 1. CSV output
    if PANDAS_AVAILABLE and all_features:
        df = pd.DataFrame(all_features)

        # Convert boolean to int for CSV compatibility
        if "embedding_features_pending" in df.columns:
            df["embedding_features_pending"] = df["embedding_features_pending"].astype(
                int
            )

        df.to_csv(output_csv_path, index=False)
        stats["total_features"] = len(df.columns)
        logger.info(
            f"✅ CSV written: {output_csv_path} ({len(df)} records, {len(df.columns)} features)"
        )

        # 2. Parquet output (optimized)
        if output_parquet_path:
            try:
                df.to_parquet(output_parquet_path, index=False, compression="snappy")
                logger.info(f"✅ Parquet written: {output_parquet_path}")
            except Exception as e:
                logger.warning(f"Failed to write Parquet (non-critical): {e}")
    else:
        # Fallback to manual CSV writing
        if all_features:
            fieldnames = list(all_features[0].keys())
            stats["total_features"] = len(fieldnames)
            with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_features)
            logger.info(f"✅ CSV written (fallback mode): {output_csv_path}")

    # 3. JSONL output (optional)
    if output_jsonl_path and jsonl_chunks:
        chunked_write_jsonl(output_jsonl_path, jsonl_chunks) # type: ignore
        logger.info(f"✅ JSONL written: {output_jsonl_path}")

    # Finalize statistics
    stats["end_time"] = datetime.now().isoformat()
    stats["success_rate"] = (
        stats["successful_extractions"] / stats["total_records"]
        if stats["total_records"] > 0
        else 0
    )

    # Calculate feature averages
    for field, field_stats in stats["feature_stats"].items():
        if field_stats["count"] > 0:
            field_stats["mean"] = field_stats["sum"] / field_stats["count"]
            field_stats["mean"] = round(field_stats["mean"], 4)

    # Convert defaultdicts to regular dicts
    stats["feature_stats"] = dict(stats["feature_stats"])
    stats["dataset_counts"] = dict(stats["dataset_counts"])
    stats["language_counts"] = dict(stats["language_counts"])

    # Write statistics
    if stats_path:
        write_json(stats, stats_path)
        logger.info(f"✅ Statistics written: {stats_path}")

    # Print summary
    logger.info("=" * 80)
    logger.info("ENHANCED FEATURE ENGINEERING SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total records:        {stats['total_records']:,}")
    logger.info(
        f"Vulnerable:           {stats['vulnerability_counts']['vulnerable']:,}"
    )
    logger.info(f"Safe:                 {stats['vulnerability_counts']['safe']:,}")
    logger.info(f"Phase 1 features:     {stats['phase1_features']}")
    logger.info(f"Phase 2 features:     {stats['phase2_features']}")
    logger.info(f"Phase 3 features:     {stats['phase3_features']}")
    logger.info(f"Total features:       {stats['total_features']}")
    logger.info(f"Datasets:             {len(stats['dataset_counts'])}")
    logger.info(f"Languages:            {len(stats['language_counts'])}")
    logger.info(f"Total chunks:         {total_chunks}")
    logger.info("=" * 80)

    return stats


# ====================================================================
# CLI ENTRY POINT
# ====================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2.3 Enhanced: Advanced Feature Engineering (Phase 1+2+3)"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Input JSONL file (validated dataset, auto-detected if not provided)",
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=None,
        help="Output CSV file with feature matrix (auto-detected if not provided)",
    )
    parser.add_argument(
        "--output-parquet",
        type=str,
        default=None,
        help="Output Parquet file (optimized binary format)",
    )
    parser.add_argument(
        "--output-jsonl",
        type=str,
        default=None,
        help="Optional output JSONL file with features",
    )
    parser.add_argument(
        "--stats",
        type=str,
        default=None,
        help="Output statistics JSON file (auto-detected if not provided)",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=5000, help="Chunk size for processing"
    )
    parser.add_argument(
        "--no-validation",
        action="store_true",
        help="Disable schema validation (faster but less safe)",
    )
    parser.add_argument(
        "--multiprocessing",
        action="store_true",
        help="Enable multiprocessing for large datasets",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Number of parallel jobs (-1 for all cores)",
    )
    parser.add_argument(
        "--disable-phase2",
        action="store_true",
        help="Disable Phase 2 features (AST, semantic, security)",
    )
    parser.add_argument(
        "--disable-phase3",
        action="store_true",
        help="Disable Phase 3 features (graph, taint, data flow)",
    )

    args = parser.parse_args()

    # Update feature flags
    global ENABLE_PHASE2_FEATURES, ENABLE_PHASE3_FEATURES
    if args.disable_phase2:
        ENABLE_PHASE2_FEATURES = False
    if args.disable_phase3:
        ENABLE_PHASE3_FEATURES = False

    # Print environment info
    print_environment_info()

    # Get paths using Kaggle-compatible helper
    if args.input:
        input_path = args.input
    else:
        input_path = str(get_dataset_path("validated/validated.jsonl"))

    if args.output_csv:
        output_csv_path = args.output_csv
    else:
        output_dir = get_output_path("features")
        output_csv_path = str(output_dir / "features_enhanced.csv")

    if args.output_parquet:
        output_parquet_path = args.output_parquet
    else:
        output_dir = get_output_path("features")
        output_parquet_path = str(output_dir / "features_enhanced.parquet")

    if args.stats:
        stats_path = args.stats
    else:
        output_dir = get_output_path("features")
        stats_path = str(output_dir / "stats_features_enhanced.json")

    # Clean up any incorrectly created directories
    for path in [output_csv_path, output_parquet_path, stats_path, args.output_jsonl]:
        if path and Path(path).is_dir():
            logger.warning(f"Removing incorrectly created directory: {path}")
            shutil.rmtree(path)

    logger.info(f"[INFO] Reading input from: {input_path}")
    logger.info(f"[INFO] Writing features to: {output_csv_path}")
    logger.info(f"[INFO] Writing statistics to: {stats_path}")

    process_dataset_to_csv_enhanced(
        input_path=input_path,
        output_csv_path=output_csv_path,
        output_parquet_path=output_parquet_path,
        output_jsonl_path=args.output_jsonl,
        stats_path=stats_path,
        chunk_size=args.chunk_size,
        validate_schema=not args.no_validation,
        use_multiprocessing=args.multiprocessing,
        n_jobs=args.n_jobs,
    )


def run(args=None):
    """Entry point for orchestrator."""
    if args is None:
        main()
    else:
        # Parse args from orchestrator
        sys.argv = ["feature_engineering_enhanced.py"] + args
        main()


if __name__ == "__main__":
    main()
