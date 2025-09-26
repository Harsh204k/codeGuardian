#!/usr/bin/env python3
"""
Quick balanced test runner for F1 score calculation
"""

import os
import sys
import json
import subprocess
import random
from pathlib import Path

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, parent_dir)

def load_diversevul_dataset():
    """Load and parse DiverseVul dataset"""
    dataset_path = Path("DiverseVul Dataset/diversevul_20230702.json")
    
    if not dataset_path.exists():
        print(f"❌ Dataset not found: {dataset_path}")
        return None
    
    print(f"📊 Loading dataset: {dataset_path}")
    data = []
    with open(dataset_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    
    # Separate vulnerable and safe samples
    vulnerable = []
    safe = []
    
    for item in data:
        if item.get('target') == 1:
            vulnerable.append(item)
        else:
            safe.append(item)
    
    print(f"   Total samples: {len(data)}")
    print(f"   Vulnerable: {len(vulnerable)}")
    print(f"   Safe: {len(safe)}")
    
    return vulnerable, safe

def create_test_files(vulnerable, safe, num_each=10):
    """Create balanced test files"""
    print(f"\n🎯 Creating balanced test with {num_each} vulnerable + {num_each} safe samples...")
    
    # Create test directory
    test_dir = Path("balanced_test_files")
    test_dir.mkdir(exist_ok=True)
    
    # Clean previous files
    for file in test_dir.glob("*"):
        file.unlink()
    
    # Sample random vulnerable and safe files
    vuln_samples = random.sample(vulnerable, min(num_each, len(vulnerable)))
    safe_samples = random.sample(safe, min(num_each, len(safe)))
    
    # Create files
    for i, sample in enumerate(vuln_samples):
        ext = sample.get('file_extension', 'c')
        if not ext.startswith('.'):
            ext = f'.{ext}'
        
        file_path = test_dir / f"vuln_{i+1:03d}{ext}"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(sample.get('func', '// No code'))
        
        print(f"   ✅ {file_path.name}: vulnerable ({len(sample.get('func', ''))//1000}KB)")
    
    for i, sample in enumerate(safe_samples):
        ext = sample.get('file_extension', 'c')
        if not ext.startswith('.'):
            ext = f'.{ext}'
        
        file_path = test_dir / f"safe_{i+1:03d}{ext}"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(sample.get('func', '// No code'))
        
        print(f"   ✅ {file_path.name}: safe ({len(sample.get('func', ''))//1000}KB)")
    
    return test_dir, len(vuln_samples), len(safe_samples)

def run_codeguardian_scan(test_dir):
    """Run CodeGuardian scan on test files"""
    print(f"\n🔍 Running CodeGuardian scan on {test_dir}...")
    
    output_dir = "balanced_test_results"
    
    # Build command
    python_exe = sys.executable
    cli_script = Path("cli.py")
    
    cmd = [
        python_exe, str(cli_script), 
        "scan", str(test_dir),
        "-o", output_dir,
        "-n", "balanced_test",
        "-f", "sarif",
        "-p", "balanced"
    ]
    
    print(f"   📋 Command: {' '.join(cmd)}")
    
    # Run scan
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"   ⚡ Scan completed in {result.returncode} seconds")
        
        if result.stdout:
            print(f"   📤 Output: {result.stdout[:200]}...")
        if result.stderr:
            print(f"   ⚠️  Errors: {result.stderr[:200]}...")
        
        return output_dir, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("   ❌ Scan timed out after 5 minutes")
        return None, False
    except Exception as e:
        print(f"   ❌ Scan failed: {e}")
        return None, False

def calculate_f1_score(results_dir, num_vuln, num_safe):
    """Calculate F1 score from SARIF results"""
    print(f"\n📊 Calculating F1 Score...")
    
    sarif_path = Path(results_dir) / "results.sarif"
    if not sarif_path.exists():
        print(f"   ❌ SARIF file not found: {sarif_path}")
        return None
    
    # Load SARIF results
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    
    # Extract findings per file
    findings_by_file = {}
    
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            for location in result.get('locations', []):
                file_uri = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                if file_uri:
                    file_name = Path(file_uri).name
                    findings_by_file[file_name] = findings_by_file.get(file_name, 0) + 1
    
    # Calculate confusion matrix
    tp = fp = tn = fn = 0
    
    # Check vulnerable files (should have findings)
    for i in range(1, num_vuln + 1):
        file_pattern = f"vuln_{i:03d}"
        found = any(file_pattern in fname for fname in findings_by_file.keys())
        if found:
            tp += 1  # Correctly identified vulnerable
        else:
            fn += 1  # Missed vulnerable
    
    # Check safe files (should have no findings)
    for i in range(1, num_safe + 1):
        file_pattern = f"safe_{i:03d}"
        found = any(file_pattern in fname for fname in findings_by_file.keys())
        if found:
            fp += 1  # Incorrectly flagged safe as vulnerable
        else:
            tn += 1  # Correctly identified safe
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    
    print(f"   📈 CONFUSION MATRIX:")
    print(f"      True Positives (TP):  {tp}")
    print(f"      False Positives (FP): {fp}")
    print(f"      True Negatives (TN):  {tn}")
    print(f"      False Negatives (FN): {fn}")
    print(f"")
    print(f"   🎯 PERFORMANCE METRICS:")
    print(f"      Precision: {precision:.3f}")
    print(f"      Recall:    {recall:.3f}")
    print(f"      F1-Score:  {f1_score:.3f}")
    print(f"      Accuracy:  {accuracy:.3f}")
    
    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'precision': precision, 'recall': recall, 
        'f1_score': f1_score, 'accuracy': accuracy
    }

def main():
    """Main execution function"""
    print("🚀 BALANCED F1 SCORE CALCULATION FOR CODEGUARDIAN")
    print("=" * 60)
    
    # Load dataset
    vulnerable, safe = load_diversevul_dataset()
    if not vulnerable or not safe:
        return 1
    
    # Create test files
    test_dir, num_vuln, num_safe = create_test_files(vulnerable, safe, num_each=10)
    
    # Run scan
    results_dir, success = run_codeguardian_scan(test_dir)
    if not success:
        print("\n❌ Scan failed, cannot calculate F1 score")
        return 1
    
    # Calculate F1 score
    metrics = calculate_f1_score(results_dir, num_vuln, num_safe)
    if metrics:
        print(f"\n🏆 FINAL RESULT: F1-Score = {metrics['f1_score']:.3f}")
        return 0
    else:
        print("\n❌ F1 calculation failed")
        return 1

if __name__ == "__main__":
    random.seed(42)  # For reproducible results
    sys.exit(main())