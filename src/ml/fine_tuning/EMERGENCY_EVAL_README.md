# 🚨 Emergency Checkpoint Evaluation Guide

## Problem: Can't Find Checkpoint Files?

If you're getting **"Checkpoint not found"** errors, follow these steps:

---

## Step 1: Find Your Checkpoints

### Method A: Use the finder script (Recommended)
```bash
cd /kaggle/working/codeGuardian/src/ml/fine_tuning
python find_checkpoints.py
```

This will:
- ✅ Search all common locations
- ✅ Show file sizes and modification times
- ✅ Give you exact paths to use

### Method B: Use the eval script's finder
```bash
python eval_saved_checkpoint.py --find-checkpoints
```

### Method C: Manual search
```bash
# Search in working directory
find /kaggle/working -name "*.pt" -o -name "*.pth"

# Or list checkpoints directory
ls -lh /kaggle/working/checkpoints/
ls -lh /kaggle/working/
```

---

## Step 2: Evaluate Your Checkpoint

Once you know where your checkpoint is, use ONE of these methods:

### Option 1: Auto-Find (Easiest)
```bash
python eval_saved_checkpoint.py --model codebert --auto
```

The script will automatically find and use the latest checkpoint!

### Option 2: Specify Path (Most Reliable)
```bash
# Use the EXACT path from Step 1
python eval_saved_checkpoint.py \
    --model codebert \
    --checkpoint /kaggle/working/your_actual_checkpoint_name.pt
```

### Option 3: Common Checkpoint Names

Try these common checkpoint paths:

```bash
# Best model checkpoint
python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/best_model.pt
python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/codebert_best.pt

# Epoch checkpoints
python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/checkpoint_epoch_3.pt
python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/epoch_3.pt

# In checkpoints folder
python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/checkpoints/best_model.pt
```

---

## Step 3: Check Dataset Path

The eval script also needs test data. Default path:
```
/kaggle/input/datasets-codebert/test_data.pt
```

If your test data is elsewhere, specify it:
```bash
python eval_saved_checkpoint.py \
    --model codebert \
    --checkpoint /kaggle/working/checkpoint.pt \
    --test-data /kaggle/input/your-dataset/test_data.pt
```

---

## Common Issues & Solutions

### Issue 1: "Checkpoint not found"
**Solution**: Run `python find_checkpoints.py` to see actual checkpoint locations

### Issue 2: "Test dataset not found"
**Solution**: Check if test data exists:
```bash
ls -lh /kaggle/input/*/test_data.pt
```

### Issue 3: Checkpoint path has spaces
**Solution**: Use quotes:
```bash
python eval_saved_checkpoint.py --checkpoint "/path/with spaces/checkpoint.pt"
```

### Issue 4: Checkpoint is in input dataset (read-only)
**Solution**: This is fine! The script can read from `/kaggle/input/`

---

## Full Example Workflow

```bash
# 1. Navigate to script directory
cd /kaggle/working/codeGuardian/src/ml/fine_tuning

# 2. Find checkpoints
python find_checkpoints.py

# 3. Copy the checkpoint path shown, then run:
python eval_saved_checkpoint.py \
    --model codebert \
    --checkpoint <PASTE_PATH_HERE>

# Example output from step 2 might show:
# /kaggle/working/checkpoint_epoch_3.pt

# Then you'd run:
python eval_saved_checkpoint.py \
    --model codebert \
    --checkpoint /kaggle/working/checkpoint_epoch_3.pt
```

---

## Understanding Checkpoint Naming

Your training script saves checkpoints with these names:

### Default Names (from train_codebert_lora.py)
- `best_model.pt` - Best model based on validation F1
- `checkpoint_epoch_1.pt` - Epoch 1 checkpoint
- `checkpoint_epoch_2.pt` - Epoch 2 checkpoint  
- `checkpoint_epoch_3.pt` - Epoch 3 checkpoint (usually the best!)

### Location
By default saved to: `/kaggle/working/checkpoints/`

But might also be in: `/kaggle/working/` (if checkpoints folder doesn't exist)

---

## Quick Troubleshooting Commands

```bash
# See what files are in working directory
ls -lh /kaggle/working/

# See what files are in checkpoints folder
ls -lh /kaggle/working/checkpoints/ 2>/dev/null || echo "No checkpoints folder"

# Find ALL .pt files
find /kaggle -name "*.pt" 2>/dev/null | head -20

# Check disk space
df -h /kaggle/working
```

---

## Still Having Issues?

1. **Verify training completed**: Check your training logs to confirm checkpoints were saved
2. **Check training script output**: Look for lines like "✓ Checkpoint saved: /path/to/checkpoint.pt"
3. **Verify file exists**: Run `ls -lh <checkpoint_path>` with the exact path
4. **Check permissions**: Run `stat <checkpoint_path>` to verify file is readable

---

## Success! What's Next?

Once evaluation completes, you'll see:
- ✅ Test Loss
- ✅ Test Accuracy
- ✅ Test Precision
- ✅ Test Recall
- ✅ Test F1 Score
- ✅ Confusion Matrix

Your training was NOT wasted! 🎉
