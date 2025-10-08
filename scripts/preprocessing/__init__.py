"""
Preprocessing module for CodeGuardian Phase 2.1

This module contains all dataset-specific preprocessing scripts that convert
raw data formats into the unified schema.

Available preprocessors:
- prepare_devign: FFmpeg/Qemu vulnerabilities
- prepare_zenodo: Multi-language CWE/CVE dataset
- prepare_diversevul: Multi-language with label noise
- prepare_github_ppakshad: Excel-based function data
- prepare_codexglue: C defect detection
- prepare_megavul: Graph-based C/C++ dataset
- prepare_juliet: NIST synthetic CWE test cases
"""

__all__ = [
    'prepare_devign',
    'prepare_zenodo',
    'prepare_diversevul',
    'prepare_github_ppakshad',
    'prepare_codexglue',
    'prepare_megavul',
    'prepare_juliet',
]
