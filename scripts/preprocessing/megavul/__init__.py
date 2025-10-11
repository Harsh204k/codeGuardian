"""
MegaVul Preprocessing Module
=============================

Scalable preprocessing system for the 100GB MegaVul dataset optimized for
Kaggle Free Tier (20GB disk limit) with Google Drive persistence.

Modules:
    - prepare_megavul: Main orchestrator for chunked preprocessing
    - chunk_manager: Chunk splitting and streaming
    - drive_sync: Google Drive upload/download/verification
    - utils_megavul: Normalization, schema validation, logging
    - postprocess_megavul: Merge chunks into final dataset
    - merge_metadata: Enrich with CWE/CVE/repo metadata

Author: CodeGuardian Team
Version: 1.0.0
Date: 2025-10-11
"""

__version__ = "1.0.0"
__all__ = [
    "prepare_megavul",
    "chunk_manager",
    "drive_sync",
    "utils_megavul",
    "postprocess_megavul",
    "merge_metadata"
]
