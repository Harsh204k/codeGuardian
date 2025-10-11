# 🎨 Pipeline Architecture Diagram

## 📊 Data Flow Visualization

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     INPUT: Raw Preprocessed Datasets                      │
│                                                                           │
│  devign/processed/raw_cleaned.jsonl                                      │
│  diversevul/processed/raw_cleaned.jsonl                                  │
│  juliet/processed/raw_cleaned.jsonl                                      │
│  zenodo/processed/raw_cleaned.jsonl                                      │
│  codexglue_defect/processed/raw_cleaned.jsonl                            │
│  [megavul/processed/raw_cleaned.jsonl] ← Future                          │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: NORMALIZATION                                 │
│                                                                           │
│  For each dataset:                                                        │
│    1. Load JSONL (streaming, line-by-line)                               │
│    2. Extract fields with fallbacks                                      │
│    3. Normalize language names (C, C++, Java, etc.)                      │
│    4. Normalize CWE/CVE IDs (CWE-XXX, CVE-YYYY-XXXXX)                    │
│    5. Auto-fill missing CWE from description                             │
│    6. Derive attack type from CWE (50+ mappings)                         │
│    7. Auto-score severity (low/medium/high/critical)                     │
│    8. Compute SHA-256 code hash                                          │
│    9. Count function length                                              │
│   10. Extract imports (language-specific)                                │
│   11. Generate UUID, timestamps                                          │
│   12. Sanitize UTF-8 encoding                                            │
│   13. Validate required fields                                           │
│   14. Save normalized output                                             │
│                                                                           │
│  Output per dataset:                                                      │
│    → datasets/<dataset>/normalized/normalized.jsonl                      │
│    → datasets/<dataset>/normalized/stats.json                            │
│    → logs/normalization/<dataset>.log                                    │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              PHASE 2: DEDUPLICATION (Optional: --deduplicate)             │
│                                                                           │
│  1. Collect all normalized records                                        │
│  2. Group by code_hash (SHA-256)                                         │
│  3. Keep first occurrence per hash                                       │
│  4. Track duplicates removed per dataset                                 │
│  5. Log deduplication statistics                                         │
│                                                                           │
│  Example results:                                                         │
│    Before: 1,108,214 records                                             │
│    After:  1,095,437 records                                             │
│    Removed: 12,777 duplicates                                            │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                PHASE 3: MERGING & STATISTICS                              │
│                                                                           │
│  1. Merge all normalized datasets                                         │
│  2. Generate overall statistics:                                          │
│     • Total records, vulnerability ratio                                 │
│     • Language distribution                                              │
│     • CWE/CVE coverage                                                   │
│     • Severity distribution                                              │
│     • Attack type distribution                                           │
│     • Project distribution                                               │
│                                                                           │
│  3. Create output artifacts:                                              │
│     • final_merged_dataset.jsonl                                         │
│     • merged_stats.json                                                  │
│     • stats_summary.csv                                                  │
│     • combined_report.md (Markdown)                                      │
│     • schema.json (Documentation)                                        │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         OUTPUT: Unified Dataset                           │
│                                                                           │
│  datasets/combined/                                                       │
│  ├── final_merged_dataset.jsonl  ← ⭐ Main unified dataset               │
│  ├── merged_stats.json            ← Overall statistics                   │
│  ├── stats_summary.csv            ← Per-dataset CSV                      │
│  ├── combined_report.md           ← Markdown audit report                │
│  └── schema.json                  ← Schema documentation                 │
│                                                                           │
│  Ready for:                                                               │
│  ✅ Feature Engineering (M1-M15)                                          │
│  ✅ Static Analysis Integration                                           │
│  ✅ ML Model Training                                                     │
│  ✅ LLM Fine-tuning                                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

## 🔄 Record Transformation Flow

```
INPUT RECORD (raw_cleaned.jsonl)
┌────────────────────────────────┐
│ {                              │
│   "func": "void foo() {...}",  │
│   "target": 1,                 │
│   "project": "linux",          │
│   "commit_id": "abc123",       │
│   "cwe": "79"                  │
│ }                              │
└────────────┬───────────────────┘
             │
             ▼
      NORMALIZATION
             │
             ▼
OUTPUT RECORD (normalized.jsonl)
┌────────────────────────────────────────────────────────┐
│ {                                                      │
│   "id": "550e8400-e29b-41d4-a716-446655440000",       │
│   "language": "C",                                     │
│   "dataset": "devign",                                 │
│   "source": null,                                      │
│   "code": "void foo() {...}",                          │
│   "is_vulnerable": 1,                                  │
│   "attack_type": "Cross-Site Scripting (XSS)",         │
│   "severity": "medium",                                │
│   "cwe_id": "CWE-79",                                  │
│   "cve_id": null,                                      │
│   "description": null,                                 │
│   "fix_available": null,                               │
│   "patch_commit": null,                                │
│   "project": "linux",                                  │
│   "file_name": null,                                   │
│   "method_name": "foo",                                │
│   "commit_id": "abc123",                               │
│   "line_range": null,                                  │
│   "code_hash": "d3f5a9b2...",                          │
│   "metrics": null,                                     │
│   "function_length": 15,                               │
│   "imports_used": ["stdio.h", "stdlib.h"],            │
│   "dependencies": null,                                │
│   "taint_flows": null,                                 │
│   "record_created": "2025-10-11T14:35:22.123456+00:00",│
│   "record_updated": "2025-10-11T14:35:22.123456+00:00",│
│   "processing_stage": "normalized",                    │
│   "review_status": "auto_verified"                     │
│ }                                                      │
└────────────────────────────────────────────────────────┘
```

## 🎯 CWE Intelligence System

```
CWE-89 ──┬─→ Attack Type: "SQL Injection"
         └─→ Severity: "high"

CWE-119 ─┬─→ Attack Type: "Buffer Overflow"
         └─→ Severity: "critical"

CWE-79 ──┬─→ Attack Type: "Cross-Site Scripting (XSS)"
         └─→ Severity: "medium"

CWE-787 ─┬─→ Attack Type: "Out-of-bounds Write"
         └─→ Severity: "critical"

CWE-416 ─┬─→ Attack Type: "Use After Free"
         └─→ Severity: "critical"

... and 45+ more mappings
```

## 📊 Statistics Generation

```
Per-Dataset Stats                    Overall Stats
┌─────────────────────┐             ┌─────────────────────────┐
│ devign              │             │ Total: 1,095,437        │
│ ├─ Total: 27,318    │             │ Vulnerable: 111,234     │
│ ├─ Vuln: 2,732      │             │ Languages: 12           │
│ ├─ Langs: 2         │───────┐     │ CWEs: 267               │
│ └─ CWEs: 45         │       │     │ Projects: 1,523         │
└─────────────────────┘       │     └─────────────────────────┘
                              │
┌─────────────────────┐       │
│ diversevul          │       │
│ ├─ Total: 826,318   │       │
│ ├─ Vuln: 82,632     │       │
│ ├─ Langs: 8         │───────┼──→ MERGE ──→ merged_stats.json
│ └─ CWEs: 178        │       │              stats_summary.csv
└─────────────────────┘       │              combined_report.md
                              │
┌─────────────────────┐       │
│ juliet              │       │
│ ├─ Total: 152,674   │       │
│ ├─ Vuln: 15,267     │       │
│ ├─ Langs: 3         │───────┘
│ └─ CWEs: 118        │
└─────────────────────┘
```

## 🔧 CLI Command Flow

```
User Command:
  python normalize_and_merge_all.py --datasets devign diversevul --deduplicate

                │
                ▼
         Parse Arguments
                │
                ▼
         Setup Directories
                │
                ▼
    ┌───────────────────────┐
    │  For each dataset:     │
    │  1. Load & Normalize   │
    │  2. Save normalized    │
    │  3. Generate stats     │
    └───────────┬───────────┘
                │
                ▼
       Collect All Records
                │
                ▼
    ┌───────────────────────┐
    │  Deduplication:        │
    │  1. Group by hash      │
    │  2. Remove duplicates  │
    │  3. Track stats        │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │  Merge & Stats:        │
    │  1. Merge all records  │
    │  2. Generate stats     │
    │  3. Create reports     │
    │  4. Save outputs       │
    └───────────┬───────────┘
                │
                ▼
         Print Summary
                │
                ▼
              Done! ✅
```

## 🧠 Enrichment Pipeline

```
Raw Code
    │
    ▼
┌─────────────────────────────┐
│  Normalization              │
│  • Remove extra whitespace  │
│  • Standardize formatting   │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Hashing                    │
│  • Normalize (strip, lower) │
│  • Compute SHA-256          │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Metrics Extraction         │
│  • Count lines              │
│  • Extract imports          │
│  • Detect language features │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  CWE Intelligence           │
│  • Map to attack type       │
│  • Assign severity          │
│  • Extract from description │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Metadata Addition          │
│  • Generate UUID            │
│  • Add timestamps           │
│  • Set processing stage     │
└──────────┬──────────────────┘
           │
           ▼
    Enriched Record
```

## 📈 Quality Metrics

```
Validation Checks:
┌─────────────────────────────────────┐
│ ✅ Required Fields Present          │
│    • id, code, label, language      │
│    • dataset                        │
│                                     │
│ ✅ Data Type Validation             │
│    • is_vulnerable: int (0 or 1)    │
│    • language: string               │
│    • code: non-empty string         │
│                                     │
│ ✅ Format Validation                │
│    • CWE-XXX pattern                │
│    • CVE-YYYY-XXXXX pattern         │
│    • UUID format                    │
│    • ISO timestamp format           │
│                                     │
│ ✅ Encoding Validation              │
│    • Valid UTF-8                    │
│    • No null bytes                  │
│    • Sanitized characters           │
└─────────────────────────────────────┘
```

---

**This diagram illustrates the complete end-to-end pipeline architecture!** 🚀
