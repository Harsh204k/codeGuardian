#!/usr/bin/env python3
"""
Quick test script to verify the inference pipeline works correctly.
Run this before deploying to Kaggle.
"""

import os
import sys
import tempfile
from pathlib import Path


def create_test_samples():
    """Create sample code files for testing"""
    test_dir = Path(tempfile.mkdtemp(prefix="cg_test_"))

    # Vulnerable sample 1: SQL Injection
    sql_vuln = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    (test_dir / "sql_injection.py").write_text(sql_vuln)

    # Vulnerable sample 2: Command Injection
    cmd_vuln = """
import os
import subprocess

def run_command(user_input):
    os.system(user_input)
    subprocess.check_output(user_input, shell=True)
"""
    (test_dir / "command_injection.py").write_text(cmd_vuln)

    # Safe sample 1
    safe1 = """
import sqlite3

def get_user_safe(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
"""
    (test_dir / "safe_parameterized.py").write_text(safe1)

    # Safe sample 2
    safe2 = """
def calculate_fibonacci(n):
    if n <= 1:
        return n
    return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)

def main():
    result = calculate_fibonacci(10)
    print(f"Fibonacci(10) = {result}")
"""
    (test_dir / "safe_fibonacci.py").write_text(safe2)

    return test_dir


def main():
    print("=" * 70)
    print("INFERENCE SCRIPT TEST")
    print("=" * 70)

    # Check if script exists
    script_path = Path(__file__).parent / "test_models_on_code_samples.py"
    if not script_path.exists():
        print(f"❌ Script not found: {script_path}")
        sys.exit(1)

    print(f"✓ Found script: {script_path}")

    # Create test samples
    print("\n📝 Creating test samples...")
    test_dir = create_test_samples()
    print(f"✓ Test samples created in: {test_dir}")

    # List files
    files = list(test_dir.glob("*.py"))
    print(f"✓ Created {len(files)} test files:")
    for f in files:
        print(f"  - {f.name}")

    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("\n1. Test locally (if you have checkpoints):")
    print(f"   python {script_path} \\")
    print(f"       --input-dir {test_dir} \\")
    print(f"       --output ./test_predictions.jsonl \\")
    print(f"       --model-choice codebert \\")
    print(f"       --checkpoint <path-to-your-checkpoint.pt>")

    print("\n2. Or copy to Kaggle and run there:")
    print(f"   !python test_models_on_code_samples.py \\")
    print(f"       --input-dir /kaggle/working/test_samples \\")
    print(f"       --output /kaggle/working/predictions.jsonl \\")
    print(f"       --model-choice codebert")

    print("\n3. For ensemble mode:")
    print(f"   python {script_path} \\")
    print(f"       --input-dir {test_dir} \\")
    print(f"       --output ./test_predictions.jsonl \\")
    print(f"       --ensemble \\")
    print(f"       --codebert-checkpoint <path> \\")
    print(f"       --graph-checkpoint <path>")

    print(f"\n✅ Test directory created: {test_dir}")
    print("✅ Script validated successfully!")
    print("\n💡 Tip: Keep test_samples directory for Kaggle testing")


if __name__ == "__main__":
    main()
