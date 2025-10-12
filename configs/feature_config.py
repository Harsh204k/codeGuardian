"""
Configuration for Enhanced Feature Engineering Pipeline
=======================================================

Control feature extraction phases and performance settings.
"""

# ====================================================================
# FEATURE PHASE TOGGLES
# ====================================================================

# Enable/disable feature extraction phases
ENABLE_PHASE1_FEATURES = (
    True  # Basic metrics, lexical, complexity, entropy (32 features)
)
ENABLE_PHASE2_FEATURES = True  # AST, semantic, security lexical (~27 features)
ENABLE_PHASE3_FEATURES = True  # Graph, taint, data flow (~15 features)
ENABLE_EMBEDDING_PREP = (
    True  # Flag for CodeBERT embeddings (to be added during training)
)

# ====================================================================
# PERFORMANCE SETTINGS
# ====================================================================

# Processing settings
DEFAULT_CHUNK_SIZE = 5000  # Smaller chunks for enhanced features
MULTIPROCESSING_ENABLED = True  # Enable parallel processing
N_JOBS = -1  # Number of parallel jobs (-1 = all cores)

# Memory management
MAX_MEMORY_USAGE_GB = 8  # Maximum memory usage in GB
ENABLE_MEMORY_PROFILING = False  # Enable memory profiling (slower)

# Kaggle-specific optimizations
KAGGLE_MODE = True  # Optimize for Kaggle environment
TARGET_RUNTIME_MINUTES = 15  # Target runtime for full dataset

# ====================================================================
# FEATURE-SPECIFIC SETTINGS
# ====================================================================

# AST parsing
AST_PARSE_TIMEOUT_SECONDS = 1  # Timeout for AST parsing
AST_MAX_DEPTH = 50  # Maximum AST depth to traverse
ENABLE_PYTHON_AST_ONLY = True  # Only use Python AST for Python code

# Graph construction
CFG_MAX_NODES = 1000  # Maximum CFG nodes to construct
CFG_TIMEOUT_SECONDS = 2  # Timeout for CFG construction
ENABLE_NETWORKX_CACHING = True  # Cache NetworkX graphs

# Taint analysis
TAINT_MAX_DISTANCE = 50  # Maximum source-sink distance to track
TAINT_ANALYSIS_TIMEOUT = 1  # Timeout for taint analysis

# ====================================================================
# VALIDATION SETTINGS
# ====================================================================

# Schema validation
VALIDATE_ORIGINAL_FIELDS = True  # Ensure all 32 original fields preserved
VALIDATE_PHASE1_FIELDS = True  # Validate Phase 1 features
VALIDATE_PHASE2_FIELDS = True  # Validate Phase 2 features
VALIDATE_PHASE3_FIELDS = True  # Validate Phase 3 features

# Data quality checks
CHECK_MISSING_VALUES = True  # Check for missing/null values
CHECK_FEATURE_RANGES = True  # Validate feature value ranges
CHECK_CODE_INTEGRITY = True  # Ensure code field is preserved
CHECK_LABEL_DISTRIBUTION = True  # Validate vulnerability labels

# ====================================================================
# OUTPUT SETTINGS
# ====================================================================

# Output formats
SAVE_CSV = True  # Save as CSV
SAVE_PARQUET = True  # Save as Parquet (optimized)
SAVE_JSONL = False  # Save as JSONL (optional, large)
SAVE_STATS = True  # Save statistics JSON

# Compression
PARQUET_COMPRESSION = "snappy"  # Parquet compression: snappy, gzip, none
CSV_COMPRESSION = None  # CSV compression: gzip, None

# ====================================================================
# LOGGING SETTINGS
# ====================================================================

LOG_LEVEL = "INFO"  # Logging level: DEBUG, INFO, WARNING, ERROR
LOG_TO_FILE = False  # Save logs to file
LOG_FILE_PATH = "logs/feature_engineering_enhanced.log"

# Progress tracking
ENABLE_PROGRESS_BAR = True  # Show progress bars (tqdm)
LOG_CHUNK_PROGRESS = True  # Log progress for each chunk
LOG_FEATURE_STATS = True  # Log feature statistics

# ====================================================================
# ERROR HANDLING
# ====================================================================

# Error recovery
CONTINUE_ON_ERROR = True  # Continue processing on feature extraction errors
FILL_MISSING_WITH_DEFAULTS = True  # Fill missing features with defaults
LOG_ERRORS = True  # Log feature extraction errors

# Fallback behavior
USE_HEURISTICS_ON_PARSE_FAIL = True  # Use heuristics if AST parsing fails
SKIP_HEAVY_FEATURES_ON_TIMEOUT = True  # Skip time-consuming features on timeout

# ====================================================================
# KAGGLE ENVIRONMENT DETECTION
# ====================================================================


def is_kaggle_environment() -> bool:
    """Detect if running in Kaggle environment."""
    import os

    return os.path.exists("/kaggle/working") or "KAGGLE_KERNEL_RUN_TYPE" in os.environ


# ====================================================================
# AUTO-CONFIGURATION
# ====================================================================


def auto_configure():
    """
    Auto-configure settings based on environment.

    Adjusts settings for Kaggle vs local development.
    """
    global DEFAULT_CHUNK_SIZE, MULTIPROCESSING_ENABLED, TARGET_RUNTIME_MINUTES
    global SAVE_JSONL, LOG_TO_FILE

    if is_kaggle_environment():
        # Kaggle optimizations
        DEFAULT_CHUNK_SIZE = 3000  # Smaller chunks for Kaggle
        MULTIPROCESSING_ENABLED = True
        TARGET_RUNTIME_MINUTES = 15
        SAVE_JSONL = False  # Don't save JSONL on Kaggle (too large)
        LOG_TO_FILE = False
        print("🔧 Auto-configured for Kaggle environment")
    else:
        # Local development settings
        DEFAULT_CHUNK_SIZE = 5000
        MULTIPROCESSING_ENABLED = True
        TARGET_RUNTIME_MINUTES = 30
        SAVE_JSONL = False
        LOG_TO_FILE = True
        print("🔧 Auto-configured for local development")


# ====================================================================
# EXPORT CONFIGURATION
# ====================================================================


def get_config() -> dict:
    """Get configuration as dictionary."""
    return {
        # Phase toggles
        "enable_phase1": ENABLE_PHASE1_FEATURES,
        "enable_phase2": ENABLE_PHASE2_FEATURES,
        "enable_phase3": ENABLE_PHASE3_FEATURES,
        "enable_embedding_prep": ENABLE_EMBEDDING_PREP,
        # Performance
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "multiprocessing": MULTIPROCESSING_ENABLED,
        "n_jobs": N_JOBS,
        # Output
        "save_csv": SAVE_CSV,
        "save_parquet": SAVE_PARQUET,
        "save_jsonl": SAVE_JSONL,
        "save_stats": SAVE_STATS,
        # Validation
        "validate_schema": VALIDATE_ORIGINAL_FIELDS,
        "check_code_integrity": CHECK_CODE_INTEGRITY,
        # Error handling
        "continue_on_error": CONTINUE_ON_ERROR,
        "fill_defaults": FILL_MISSING_WITH_DEFAULTS,
    }


# Auto-configure on import
auto_configure()
