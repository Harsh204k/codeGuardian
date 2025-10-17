"""
Quick script to find all checkpoint files on Kaggle
"""

import os
import glob
from datetime import datetime

print("="*70)
print("SEARCHING FOR CHECKPOINT FILES")
print("="*70)

# Search patterns
search_locations = [
    "/kaggle/working",
    "/kaggle/input",
    ".",
]

found_checkpoints = []

for location in search_locations:
    if os.path.exists(location):
        print(f"\n📁 Searching: {location}")
        
        # Walk through directory
        for root, dirs, files in os.walk(location):
            for file in files:
                if file.endswith(('.pt', '.pth', '.bin')):
                    full_path = os.path.join(root, file)
                    try:
                        size_mb = os.path.getsize(full_path) / (1024 * 1024)
                        mtime = os.path.getmtime(full_path)
                        mod_time_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                        found_checkpoints.append({
                            'path': full_path,
                            'size': size_mb,
                            'modified': mod_time_str,
                            'mtime': mtime
                        })
                        print(f"  ✓ {file}")
                    except:
                        pass

print(f"\n{'='*70}")
print(f"FOUND {len(found_checkpoints)} CHECKPOINT(S)")
print(f"{'='*70}")

if found_checkpoints:
    # Sort by modification time (newest first)
    found_checkpoints.sort(key=lambda x: x['mtime'], reverse=True)
    
    print("\n📊 CHECKPOINT DETAILS:\n")
    for i, cp in enumerate(found_checkpoints, 1):
        print(f"{i}. {cp['path']}")
        print(f"   Size: {cp['size']:.2f} MB")
        print(f"   Modified: {cp['modified']}")
        print()
    
    print(f"{'='*70}")
    print("💡 TO EVALUATE A CHECKPOINT:")
    print(f"{'='*70}")
    print("\nOption 1 - Auto-find (recommended):")
    print("  python eval_saved_checkpoint.py --model codebert --auto")
    print()
    print("Option 2 - Specify checkpoint:")
    if found_checkpoints:
        latest = found_checkpoints[0]['path']
        print(f"  python eval_saved_checkpoint.py --model codebert --checkpoint {latest}")
else:
    print("\n❌ No checkpoint files found!")
    print("\nSearched locations:")
    for loc in search_locations:
        print(f"  - {loc}")
    print("\n💡 Make sure your training script saved checkpoints successfully.")
