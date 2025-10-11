#!/usr/bin/env python3
"""
Quick comparison between old and ultra-fast Juliet preprocessing.
Tests both on a small sample to show speed improvement.
"""

import time
import subprocess
import sys
from pathlib import Path

def run_command(cmd):
    """Run command and return (exit_code, time_taken)."""
    start = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    elapsed = time.time() - start
    return result.returncode, elapsed, result.stdout, result.stderr

def main():
    scripts_dir = Path(__file__).parent
    
    print("="*80)
    print("JULIET PREPROCESSING - SPEED COMPARISON TEST")
    print("="*80)
    print("\nTesting with 1,000 files...\n")
    
    # Test 1: Ultra-fast version
    print("🚀 Testing ULTRA-FAST version...")
    print("-"*80)
    cmd1 = f"python {scripts_dir}/prepare_juliet_ultra_fast.py --test"
    code1, time1, out1, err1 = run_command(cmd1)
    
    if code1 == 0:
        print(f"✅ Ultra-fast completed in {time1:.2f}s")
        # Extract stats from output
        for line in out1.split('\n'):
            if 'Processing speed' in line or 'Extraction rate' in line or 'Total records' in line:
                print(f"   {line.strip()}")
    else:
        print(f"❌ Ultra-fast failed")
        print(err1)
    
    print()
    
    # Test 2: Original version
    print("🐢 Testing ORIGINAL version...")
    print("-"*80)
    cmd2 = f"python {scripts_dir}/prepare_juliet_parallel.py --max-files 1000"
    code2, time2, out2, err2 = run_command(cmd2)
    
    if code2 == 0:
        print(f"✅ Original completed in {time2:.2f}s")
        for line in out2.split('\n'):
            if 'Total records' in line or 'Extraction' in line:
                print(f"   {line.strip()}")
    else:
        print(f"❌ Original failed")
        print(err2)
    
    # Comparison
    print()
    print("="*80)
    print("COMPARISON RESULTS")
    print("="*80)
    
    if code1 == 0 and code2 == 0:
        speedup = time2 / time1
        print(f"\n⏱️  TIMING:")
        print(f"   Original: {time2:.2f}s")
        print(f"   Ultra-fast: {time1:.2f}s")
        print(f"   Speedup: {speedup:.1f}x faster! 🚀")
        
        if speedup >= 3:
            print(f"\n✅ EXCELLENT! {speedup:.1f}x speedup achieved!")
            print("   Ready for competition! 🏆")
        elif speedup >= 2:
            print(f"\n✅ GOOD! {speedup:.1f}x speedup")
        else:
            print(f"\n⚠️  Moderate speedup: {speedup:.1f}x")
    
    elif code1 == 0:
        print("\n✅ Ultra-fast version works!")
        print(f"   Time: {time1:.2f}s")
        print("❌ Original version failed - ultra-fast is the winner!")
    
    else:
        print("\n❌ Tests failed - check errors above")
    
    print()

if __name__ == '__main__':
    main()
