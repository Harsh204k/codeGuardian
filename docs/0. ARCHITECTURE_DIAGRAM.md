# CodeGuardian Phase 2 - Refactoring Architecture Diagram

```
╔════════════════════════════════════════════════════════════════════════════╗
║                 CODEGUARDIAN PHASE 2 - MODULAR ARCHITECTURE                ║
║                           Version 3.0.0                                    ║
╚════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────┐
│                          USER ENTRY POINT                                │
│                                                                          │
│                    python scripts/run_pipeline.py                        │
│                                                                          │
│    CLI Options: --skip, --resume, --log-level, --quick-test            │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     PIPELINE ORCHESTRATOR                                │
│                   (scripts/run_pipeline.py)                              │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  Dynamic Module Discovery (importlib)                              │ │
│  │  • Auto-detects entry points (run/main/execute/process)            │ │
│  │  • Loads modules at runtime                                        │ │
│  │  • No hardcoded imports                                            │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  Phase Configuration & Dependency Management                       │ │
│  │  • Execution order: preprocessing → normalization → validation     │ │
│  │                      → features → splitting                        │ │
│  │  • Dependency checking (e.g., validation depends on normalization)│ │
│  │  • Skip/resume logic                                               │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  Logging & Error Handling                                          │ │
│  │  • Color-coded console output                                      │ │
│  │  • Comprehensive file logging (logs/phase2/pipeline_run.log)       │ │
│  │  • Module isolation (one failure doesn't stop pipeline)            │ │
│  │  • Execution summary with statistics                               │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
                    ╔═══════════════════════╗
                    ║   PHASE EXECUTION     ║
                    ╚═══════════════════════╝
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│   Phase 2.1    │     │   Phase 2.2    │     │  Phase 2.3a    │
│ PREPROCESSING  │────▶│ NORMALIZATION  │────▶│  VALIDATION    │
└────────────────┘     └────────────────┘     └────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ 7 Modules:     │     │ 1 Module:      │     │ 1 Module:      │
│                │     │                │     │                │
│ • devign       │     │ • normalize_   │     │ • validate_    │
│ • zenodo       │     │   all_datasets │     │   normalized_  │
│ • diversevul   │     │                │     │   data         │
│ • ppakshad     │     └────────────────┘     │                │
│ • codexglue    │                            └────────────────┘
│ • megavul      │
│ • juliet       │              │                       │
│                │              └───────────┬───────────┘
└────────────────┘                          │
         │                                  ▼
         │                       ┌────────────────┐
         │                       │  Phase 2.3b    │
         │                       │   FEATURES     │
         │                       └────────────────┘
         │                                  │
         │                                  ▼
         │                       ┌────────────────┐
         │                       │ 1 Module:      │
         │                       │                │
         │                       │ • feature_     │
         │                       │   engineering  │
         │                       │                │
         │                       └────────────────┘
         │                                  │
         │                                  ▼
         │                       ┌────────────────┐
         │                       │  Phase 2.3c    │
         │                       │   SPLITTING    │
         │                       └────────────────┘
         │                                  │
         │                                  ▼
         │                       ┌────────────────┐
         │                       │ 1 Module:      │
         │                       │                │
         │                       │ • split_       │
         │                       │   datasets     │
         │                       │                │
         │                       └────────────────┘
         │                                  │
         └──────────────────┬───────────────┘
                            │
                            ▼
              ╔═══════════════════════════╗
              ║    SHARED UTILITIES       ║
              ║  (scripts/utils/)         ║
              ╚═══════════════════════════╝
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│   io_utils     │ │ schema_utils   │ │ text_cleaner   │
│                │ │                │ │                │
│ • read_jsonl   │ │ • validate_    │ │ • sanitize_    │
│ • write_jsonl  │ │   record       │ │   code         │
│ • read_csv     │ │ • map_to_      │ │ • is_valid_    │
│ • ensure_dir   │ │   unified_     │ │   code         │
│                │ │   schema       │ │                │
└────────────────┘ └────────────────┘ └────────────────┘

                            │
                            ▼
              ╔═══════════════════════════╗
              ║      OUTPUT FILES         ║
              ╚═══════════════════════════╝
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│  datasets/     │ │  datasets/     │ │  datasets/     │
│  unified/      │ │  features/     │ │  processed/    │
│                │ │                │ │                │
│ • processed_   │ │ • features_    │ │ • train.jsonl  │
│   all.jsonl    │ │   all.jsonl    │ │ • val.jsonl    │
│ • validated.   │ │ • stats_       │ │ • test.jsonl   │
│   jsonl        │ │   features.    │ │ • split_       │
│ • validation_  │ │   json         │ │   summary.json │
│   report.json  │ │                │ │                │
└────────────────┘ └────────────────┘ └────────────────┘

                            │
                            ▼
              ╔═══════════════════════════╗
              ║        LOGGING            ║
              ╚═══════════════════════════╝
                            │
                            ▼
                 ┌────────────────────┐
                 │   logs/phase2/     │
                 │                    │
                 │ • pipeline_run.log │
                 │   (comprehensive   │
                 │    execution log)  │
                 └────────────────────┘

═══════════════════════════════════════════════════════════════════════════

KEY FEATURES OF REFACTORED ARCHITECTURE:

✅ Modular Organization
   • Each phase in separate subdirectory
   • Clear separation of concerns
   • Easy to extend/modify individual components

✅ Dynamic Execution
   • Automatic module discovery
   • No hardcoded imports
   • Runtime module loading

✅ Dependency Management
   • Explicit phase dependencies
   • Automatic dependency checking
   • Prevents orphaned phase execution

✅ Flexible CLI
   • Skip already-completed phases
   • Resume from specific phase
   • Adjustable log levels
   • Quick test mode

✅ Comprehensive Logging
   • Color-coded console output
   • Detailed file logs
   • Phase and module timing
   • Execution summaries

✅ Error Resilience
   • Module-level isolation
   • Graceful degradation
   • Detailed error messages
   • Ctrl+C interrupt handling

═══════════════════════════════════════════════════════════════════════════

IMPORT STRUCTURE (New):

  scripts/
    ├── preprocessing/
    │   └── prepare_devign.py
    │       from scripts.utils.io_utils import read_jsonl
    │       from scripts.utils.schema_utils import validate_record
    │
    └── utils/
        └── io_utils.py
            (no external script imports)

All modules use: from scripts.utils.* for shared utilities

═══════════════════════════════════════════════════════════════════════════
```

## Directory Structure Summary

```
codeGuardian/
├── scripts/                     ← Phase 2 Pipeline Scripts
│   ├── preprocessing/           ← 7 dataset-specific preprocessors
│   ├── normalization/           ← Dataset merging & deduplication
│   ├── validation/              ← Schema & quality validation
│   ├── features/                ← ML feature extraction
│   ├── splitting/               ← Train/val/test splitting
│   ├── utils/                   ← Shared utilities
│   ├── run_pipeline.py          ← 🚀 Dynamic orchestrator
│   └── test_refactored_structure.py  ← Verification tests
│
├── datasets/                    ← Data Storage
│   ├── <dataset>/raw/           ← Raw datasets
│   ├── unified/                 ← Normalized & validated data
│   ├── features/                ← Feature-enriched data
│   └── processed/               ← Train/val/test splits
│
├── logs/                        ← Execution Logs
│   └── phase2/
│       └── pipeline_run.log     ← Comprehensive pipeline log
│
└── docs/                        ← Documentation
    ├── REFACTORING_GUIDE.md     ← Architecture details
    ├── QUICKSTART.md            ← 5-minute guide
    └── IMPLEMENTATION_SUMMARY.md ← This refactoring summary
```

## Execution Flow

1. **User runs:** `python scripts/run_pipeline.py`
2. **Orchestrator:**
   - Parses CLI arguments
   - Sets up logging
   - Loads phase configuration
3. **For each phase (in order):**
   - Check dependencies
   - Discover modules dynamically
   - Find entry points (run/main/execute/process)
   - Execute modules with error handling
   - Log results
4. **After all phases:**
   - Print execution summary
   - Generate performance statistics
   - Exit with appropriate code

## Migration from v2.0 to v3.0

**What Changed:**
- Scripts moved to subdirectories
- Imports updated: `utils.*` → `scripts.utils.*`
- New orchestrator with dynamic discovery
- Enhanced logging and error handling

**What Stayed the Same:**
- Utility functions unchanged
- Data schema unchanged
- Output file locations unchanged
- Function signatures unchanged

**Migration Time:** ~10 minutes to update scripts, ~0 minutes for users (backward compatible)

---

**Version:** 3.0.0 (Modular Architecture)  
**Last Updated:** October 7, 2025  
**Author:** CodeGuardian Team
