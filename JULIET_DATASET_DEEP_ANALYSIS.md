# Juliet Test Suite - Deep Dataset Analysis

## 🎯 Dataset Overview

**Juliet Test Suite** is NIST's comprehensive synthetic vulnerability benchmark for testing static analysis tools.

### Statistics
- **Total Files**: 185,323 source files
  - C files: 53,830
  - C++ files: 43,698
  - Java files: 42,812
  - C# files: 44,983
- **Languages**: C, C++, Java, C#
- **CWE Categories**: 118 different vulnerability types
- **Purpose**: Synthetic test cases with known vulnerabilities

---

## 📁 Directory Structure

```
juliet/raw/
├── c/                          # C/C++ test cases
│   ├── testcases/
│   │   ├── CWE23_Relative_Path_Traversal/
│   │   │   ├── s01/           # Subdirectory for variants
│   │   │   │   ├── CWE23_..._01.c
│   │   │   │   ├── CWE23_..._01.cpp
│   │   │   │   └── ...
│   │   │   ├── s02/
│   │   │   └── ...
│   │   ├── CWE121_Stack_Based_Buffer_Overflow/
│   │   └── ... (118 CWE folders)
│   └── testcasesupport/       # Helper files (io.c, std_testcase.h)
│
├── java/src/testcases/        # Java test cases
│   ├── CWE81_XSS_Error_Message/
│   │   ├── CWE81_XSS_Error_Message__Servlet_connect_tcp_01.java
│   │   └── ...
│   └── ... (multiple CWE folders)
│
└── csharp/src/testcases/      # C# test cases
    ├── CWE36_Absolute_Path_Traversal/
    │   ├── CWE36_Absolute_Path_Traversal__Connect_tcp_01.cs
    │   └── ...
    └── ... (multiple CWE folders)
```

---

## 🔍 File Structure Analysis

### File Naming Convention

**Pattern**: `CWE{ID}_{Name}__{Variant}_{Version}.{ext}`

**Examples**:
- `CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp`
- `CWE81_XSS_Error_Message__Servlet_connect_tcp_01.java`
- `CWE36_Absolute_Path_Traversal__Connect_tcp_01.cs`

**Components**:
1. **CWE ID**: The vulnerability type (e.g., CWE23, CWE81)
2. **CWE Name**: Human-readable vulnerability name
3. **Variant**: Specific test scenario (e.g., `char_environment_ofstream`, `Servlet_connect_tcp`)
4. **Version**: Test case number (01, 02, 03, etc.)

---

## 📝 Code Structure Inside Files

### Common Pattern Across All Languages

Each file contains:

1. **Header Comment** with metadata:
   ```
   /* TEMPLATE GENERATED TESTCASE FILE
   Filename: CWE23_...cpp
   Label Definition File: CWE23_Relative_Path_Traversal.label.xml
   Template File: sources-sink-03.tmpl.cpp
   */
   ```

2. **@description Comment** (KEY METADATA):
   ```
   /*
   * @description
   * CWE: 23 Relative Path Traversal
   * BadSource: environment Read input from an environment variable
   * GoodSource: Use a fixed file name
   * Sink: ofstream
   *    BadSink : Open the file named in data using ofstream::open()
   * Flow Variant: 03 Control flow: if(5==5) and if(5!=5)
   * */
   ```

3. **Function Definitions**:
   - **`bad()` function**: Contains VULNERABLE code
   - **`good()` function**: Contains SAFE/FIXED code
   - **`goodG2B()`, `goodB2G()`, etc.**: Variant good functions

---

## 🎭 Function Patterns

### C/C++ Pattern

```cpp
namespace CWE23_Relative_Path_Traversal__char_environment_ofstream_03
{
    #ifndef OMITBAD
    void bad()  // VULNERABLE FUNCTION
    {
        char * data;
        // ... FLAWED CODE with POTENTIAL FLAW comment
    }
    #endif

    #ifndef OMITGOOD
    static void goodG2B1()  // GOOD SOURCE, BAD SINK
    {
        // ... FIX: Use a fixed file name
    }
    
    static void goodG2B2()  // Another variant
    {
        // ... FIX: Different approach
    }
    
    void good()  // Main good function (calls variants)
    {
        goodG2B1();
        goodG2B2();
    }
    #endif
}
```

### Java Pattern

```java
public class CWE81_XSS_Error_Message__Servlet_connect_tcp_01 extends AbstractTestCaseServlet
{
    /* uses badsource and badsink */
    public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;
        // ... POTENTIAL FLAW comment
    }

    public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        goodG2B(request, response);
    }

    private void goodG2B(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // ... FIX: A hardcoded string
    }
}
```

### C# Pattern

```csharp
class CWE36_Absolute_Path_Traversal__Connect_tcp_01 : AbstractTestCase
{
    #if (!OMITBAD)
    public override void Bad()
    {
        string data;
        // ... POTENTIAL FLAW comment
    }
    #endif

    #if (!OMITGOOD)
    public override void Good()
    {
        GoodG2B();
    }

    private void GoodG2B()
    {
        // ... FIX: A hardcoded string
    }
    #endif
}
```

---

## 🏷️ Label Extraction Logic

### How to Determine Vulnerability

**Key Insight**: Each file contains BOTH vulnerable AND safe code

**Label Assignment**:
1. Extract `bad()` function → Label = 1 (VULNERABLE)
2. Extract `good()` function(s) → Label = 0 (SAFE)

**Multiple Records Per File**:
- 1 vulnerable record from `bad()` function
- 1+ safe records from `good()` variants

---

## 🔧 Metadata Extraction Strategy

### From File Path
```python
file_path = "c/testcases/CWE23_Relative_Path_Traversal/s02/CWE23_...03.cpp"

# Extract:
cwe_id = "CWE-23"                    # From folder name
cwe_name = "Relative Path Traversal"  # From folder name
language = "C++"                      # From file extension
subdirectory = "s02"                  # Variant grouping
```

### From File Name
```python
filename = "CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp"

# Extract:
variant = "char_environment_ofstream"  # Source/Sink combination
version = "03"                         # Test case number
```

### From @description Comment
```python
"""
* @description
* CWE: 23 Relative Path Traversal
* BadSource: environment Read input from an environment variable
* GoodSource: Use a fixed file name
* Sink: ofstream
*    BadSink : Open the file named in data using ofstream::open()
* Flow Variant: 03 Control flow: if(5==5) and if(5!=5)
"""

# Extract:
bad_source = "environment Read input from an environment variable"
good_source = "Use a fixed file name"
sink = "ofstream"
bad_sink = "Open the file named in data using ofstream::open()"
flow_variant = "03 Control flow: if(5==5) and if(5!=5)"
```

---

## 📊 Processing Strategy

### Multi-Language Processing Pipeline

```
For each language (C, C++, Java, C#):
  ├─ Scan all CWE folders
  │   ├─ For each source file:
  │   │   ├─ Parse file header and @description
  │   │   ├─ Extract CWE from path/filename
  │   │   ├─ Extract bad() function → Create vulnerable record
  │   │   ├─ Extract good() function(s) → Create safe record(s)
  │   │   └─ Add metadata (variant, flow, source/sink)
  │   └─ Collect all records
  └─ Merge all language records
```

### Expected Output Per File

**Example**: `CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp`

**Record 1** (Vulnerable):
```json
{
  "code": "void bad() {\n  char * data;\n  ...\n}",
  "label": 1,
  "language": "C++",
  "cwe_id": "CWE-23",
  "cwe_name": "Relative Path Traversal",
  "variant": "char_environment_ofstream",
  "flow_variant": "03",
  "bad_source": "environment Read input from an environment variable",
  "bad_sink": "Open the file named in data using ofstream::open()",
  "filename": "CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp",
  "file_path": "c/testcases/CWE23_Relative_Path_Traversal/s02/...",
  "function_name": "bad",
  "dataset": "juliet"
}
```

**Record 2** (Safe):
```json
{
  "code": "void good() {\n  goodG2B1();\n  goodG2B2();\n}",
  "label": 0,
  "language": "C++",
  "cwe_id": "CWE-23",
  "cwe_name": "Relative Path Traversal",
  "variant": "char_environment_ofstream",
  "flow_variant": "03",
  "good_source": "Use a fixed file name",
  "filename": "CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp",
  "file_path": "c/testcases/CWE23_Relative_Path_Traversal/s02/...",
  "function_name": "good",
  "dataset": "juliet"
}
```

---

## 🎯 Key Extraction Rules

### 1. CWE Extraction
```python
# From folder name: "CWE23_Relative_Path_Traversal"
cwe_match = re.match(r'CWE(\d+)_(.+)', folder_name)
cwe_id = f"CWE-{cwe_match.group(1)}"  # "CWE-23"
cwe_name = cwe_match.group(2).replace('_', ' ')  # "Relative Path Traversal"
```

### 2. Function Extraction (Language-Specific)

**C/C++**:
```python
# Bad function: void bad() { ... }
bad_pattern = r'void\s+bad\s*\([^)]*\)\s*{(.*?)(?:^}|\n})'

# Good function: void good() { ... }
good_pattern = r'void\s+good\s*\([^)]*\)\s*{(.*?)(?:^}|\n})'
```

**Java**:
```python
# Bad method: public void bad(...) throws ... { ... }
bad_pattern = r'public\s+void\s+bad\s*\([^)]*\)(?:\s+throws[^{]*)?\s*{(.*?)(?:^\s*}|\n\s*})'

# Good method: public void good(...) { ... }
good_pattern = r'public\s+void\s+good\s*\([^)]*\)(?:\s+throws[^{]*)?\s*{(.*?)(?:^\s*}|\n\s*})'
```

**C#**:
```python
# Bad method: public override void Bad() { ... }
bad_pattern = r'public\s+override\s+void\s+Bad\s*\([^)]*\)\s*{(.*?)(?:^\s*}|\n\s*})'

# Good method: public override void Good() { ... }
good_pattern = r'public\s+override\s+void\s+Good\s*\([^)]*\)\s*{(.*?)(?:^\s*}|\n\s*})'
```

### 3. Description Parsing
```python
description_pattern = r'/\*\s*\*\s*@description(.*?)\*/'

# Extract fields:
# - CWE: <id> <name>
# - BadSource: <description>
# - GoodSource: <description>
# - Sink: <sink_name>
# - BadSink: <description>
# - Flow Variant: <variant>
```

---

## 📈 Expected Statistics

### Total Records (Estimated)
- Each file produces ~2-4 records (1 bad + 1-3 good variants)
- **Estimated total**: 370,000 - 740,000 records

### Distribution
```
Language Distribution:
  C:      ~110,000 - 220,000 records
  C++:    ~90,000 - 180,000 records
  Java:   ~85,000 - 170,000 records
  C#:     ~90,000 - 180,000 records

Label Distribution:
  Vulnerable (label=1):     ~185,000 records (25-33%)
  Non-vulnerable (label=0): ~370,000-555,000 records (67-75%)
  
CWE Distribution:
  118 different CWE types
  Most common: CWE-78, CWE-89, CWE-79, CWE-190, CWE-476
```

---

## 🚀 Processing Performance

### Challenges
- **185,323 files** to process
- **Regex parsing** for function extraction
- **Multi-language** support required

### Optimization Strategy
1. **Multiprocessing**: Use all CPU cores (4-8 workers)
2. **Batch Processing**: Process 1000 files per batch
3. **Lazy Loading**: Read files only when needed
4. **Progress Tracking**: TQDM for visibility
5. **Error Handling**: Skip corrupted files, log errors

### Estimated Processing Time
- Single core: ~60-90 minutes
- 4 cores: ~15-25 minutes
- 8 cores: ~10-15 minutes

---

## ✅ Validation Strategy

### Per-Record Validation
- ✓ Code is not empty
- ✓ Language is valid (C, C++, Java, C#)
- ✓ CWE ID format is correct (CWE-XXX)
- ✓ Label is 0 or 1
- ✓ Function name is extracted

### Statistics Validation
- Total records > 300,000
- Vulnerable ratio: 25-40%
- All 118 CWEs present
- All 4 languages present

---

## 🎨 Output Format

### raw_cleaned.jsonl
```jsonl
{"code": "void bad() {...}", "label": 1, "language": "C++", "cwe_id": "CWE-23", ...}
{"code": "void good() {...}", "label": 0, "language": "C++", "cwe_id": "CWE-23", ...}
{"code": "public void bad(...) {...}", "label": 1, "language": "Java", "cwe_id": "CWE-81", ...}
...
```

### stats.json
```json
{
  "total_records": 450000,
  "vulnerable_records": 150000,
  "safe_records": 300000,
  "vulnerability_ratio": 0.333,
  "languages": {
    "C": 110000,
    "C++": 95000,
    "Java": 120000,
    "C#": 125000
  },
  "unique_cwes": 118,
  "cwe_distribution": {
    "CWE-78": 5234,
    "CWE-89": 4821,
    ...
  }
}
```

---

## 🔑 Key Differences from DiverseVul

| Aspect | DiverseVul | Juliet |
|--------|------------|--------|
| **Source** | Real-world vulnerabilities | Synthetic test cases |
| **Files** | 1 JSON file (330K records) | 185K source files |
| **Structure** | Pre-labeled records | Extract from source code |
| **Labels** | Direct (target: 0/1) | Derived (bad=1, good=0) |
| **Metadata** | Commit IDs, CVEs | CWE, variant, flow |
| **Processing** | JSON parsing | Code parsing + regex |
| **Languages** | Mixed (C, Java, etc.) | Separate folders per language |
| **Splits** | Pre-defined splits | No splits (all data) |

---

## 🎯 Summary

**Juliet is a CODE PARSING challenge**, not a JSON parsing task like DiverseVul.

**Key Tasks**:
1. ✅ Walk through 185K source files across 4 languages
2. ✅ Extract CWE from folder/filename
3. ✅ Parse @description for metadata
4. ✅ Use regex to extract bad() and good() functions
5. ✅ Create labeled records (bad=1, good=0)
6. ✅ Handle multi-language syntax differences
7. ✅ Use multiprocessing for speed
8. ✅ Generate comprehensive statistics

**Next**: Build the complete preprocessing script! 🚀
