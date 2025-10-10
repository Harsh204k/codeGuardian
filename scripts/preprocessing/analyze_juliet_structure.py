#!/usr/bin/env python3
"""
Deep analysis script for Juliet Test Suite dataset.
This script analyzes the actual structure and naming conventions.
"""

import re
from pathlib import Path
from collections import defaultdict

def analyze_file_naming_pattern(file_path: Path) -> dict:
    """Analyze a single file to extract patterns."""
    filename = file_path.name
    stem = file_path.stem
    
    # Extract CWE from path or filename
    path_str = str(file_path)
    cwe_match = re.search(r'CWE[-_]?(\d+)', path_str, re.IGNORECASE)
    cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None
    
    # Check for good/bad/goodsink/badsink patterns
    lower_name = filename.lower()
    
    is_bad = False
    is_good = False
    
    # Juliet patterns
    if '_bad' in lower_name or 'bad_' in lower_name:
        is_bad = True
    elif '_good' in lower_name or 'good_' in lower_name:
        is_good = True
    
    # Read file content to check for function names
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(5000)  # First 5000 chars
            
        has_bad_func = 'bad()' in content or '_bad()' in content or 'void bad(' in content
        has_good_func = 'good()' in content or '_good()' in content or 'void good(' in content
        
        return {
            'filename': filename,
            'cwe': cwe_id,
            'is_bad_filename': is_bad,
            'is_good_filename': is_good,
            'has_bad_function': has_bad_func,
            'has_good_function': has_good_func,
            'both_functions': has_bad_func and has_good_func,
            'size': file_path.stat().st_size
        }
    except Exception as e:
        return {
            'filename': filename,
            'cwe': cwe_id,
            'error': str(e)
        }

def analyze_language_directory(lang_dir: Path, extensions: list, lang_name: str) -> dict:
    """Analyze all files for a specific language."""
    print(f"\n{'='*60}")
    print(f"ANALYZING {lang_name.upper()} FILES")
    print(f"{'='*60}")
    
    files_analyzed = []
    cwe_distribution = defaultdict(int)
    
    testcases_dir = lang_dir / "testcases" if (lang_dir / "testcases").exists() else lang_dir / "src" / "testcases"
    
    if not testcases_dir.exists():
        print(f"❌ Testcases directory not found: {testcases_dir}")
        return {}
    
    # Find all source files (limit to first 100 for speed)
    file_count = 0
    max_files = 100
    
    for ext in extensions:
        for file_path in testcases_dir.rglob(f"*{ext}"):
            if file_count >= max_files:
                break
                
            if 'support' in str(file_path).lower() or 'common' in str(file_path).lower():
                continue  # Skip support files
            
            analysis = analyze_file_naming_pattern(file_path)
            files_analyzed.append(analysis)
            file_count += 1
            
            if analysis.get('cwe'):
                cwe_distribution[analysis['cwe']] += 1
    
    # Statistics
    total_files = len(files_analyzed)
    files_with_both = sum(1 for f in files_analyzed if f.get('both_functions'))
    files_bad_only = sum(1 for f in files_analyzed if f.get('has_bad_function') and not f.get('has_good_function'))
    files_good_only = sum(1 for f in files_analyzed if f.get('has_good_function') and not f.get('has_bad_function'))
    
    print(f"\n📊 Statistics for {lang_name}:")
    print(f"  Total files: {total_files}")
    print(f"  Files with BOTH bad() and good() functions: {files_with_both}")
    print(f"  Files with ONLY bad() function: {files_bad_only}")
    print(f"  Files with ONLY good() function: {files_good_only}")
    print(f"  Unique CWEs: {len(cwe_distribution)}")
    
    print(f"\n🔍 File Structure Pattern:")
    if files_with_both > 0:
        print(f"  ✅ PATTERN: Most files contain BOTH bad() and good() functions")
        print(f"     → Need to extract MULTIPLE records per file!")
        print(f"     → Each file = 2 records (1 vulnerable + 1 safe)")
    
    print(f"\n📝 Sample files analyzed:")
    for i, file_info in enumerate(files_analyzed[:5]):
        print(f"  {i+1}. {file_info.get('filename')}")
        print(f"     - CWE: {file_info.get('cwe')}")
        print(f"     - Has bad(): {file_info.get('has_bad_function')}")
        print(f"     - Has good(): {file_info.get('has_good_function')}")
        print(f"     - Both: {file_info.get('both_functions')}")
    
    print(f"\n🏷️  Top 10 CWEs:")
    for cwe, count in sorted(cwe_distribution.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {cwe}: {count} files")
    
    return {
        'total_files': total_files,
        'files_with_both': files_with_both,
        'files_bad_only': files_bad_only,
        'files_good_only': files_good_only,
        'unique_cwes': len(cwe_distribution),
        'cwe_distribution': dict(cwe_distribution),
        'samples': files_analyzed[:10]
    }

def main():
    base_dir = Path(r"c:\Users\urvag\Downloads\Projects\Hackathon\DPIIT\codeGuardian\datasets\juliet\raw")
    
    print("="*80)
    print("JULIET TEST SUITE - DEEP STRUCTURE ANALYSIS")
    print("="*80)
    
    # Analyze each language
    results = {}
    
    # C/C++
    c_dir = base_dir / "c"
    if c_dir.exists():
        results['c'] = analyze_language_directory(c_dir, ['.c'], 'C')
    
    # Java
    java_dir = base_dir / "java"
    if java_dir.exists():
        results['java'] = analyze_language_directory(java_dir, ['.java'], 'Java')
    
    # C#
    csharp_dir = base_dir / "csharp"
    if csharp_dir.exists():
        results['csharp'] = analyze_language_directory(csharp_dir, ['.cs'], 'C#')
    
    # Summary
    print("\n" + "="*80)
    print("CRITICAL FINDINGS")
    print("="*80)
    
    total_files = sum(r.get('total_files', 0) for r in results.values())
    total_with_both = sum(r.get('files_with_both', 0) for r in results.values())
    
    print(f"\n🎯 KEY INSIGHT:")
    print(f"  Total source files: {total_files}")
    print(f"  Files with BOTH functions: {total_with_both}")
    
    if total_with_both > total_files * 0.8:  # More than 80%
        print(f"\n  ⚠️  CRITICAL: {(total_with_both/total_files*100):.1f}% of files have BOTH bad() and good()")
        print(f"  📌 Current script processes 1 record per file → WRONG!")
        print(f"  ✅ Should extract 2 records per file:")
        print(f"     1. Extract bad() function → label=1 (vulnerable)")
        print(f"     2. Extract good() function → label=0 (safe)")
        print(f"\n  💡 Expected output records: ~{total_files * 2} (not {total_files})")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    main()
