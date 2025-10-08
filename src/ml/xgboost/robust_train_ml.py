#!/usr/bin/env python3
"""
Robust ML Training Pipeline - Enhanced CodeBERT Vulnerability Detection
Handles network issues with better download strategy and resumption
"""

import json
import torch
import logging
import os
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from transformers import TrainerCallback, EarlyStoppingCallback
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
from datetime import datetime
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RobustDataset(torch.utils.data.Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = str(self.texts[idx])
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(self.labels[idx], dtype=torch.long)
        }

def compute_metrics(eval_pred):
    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)
    
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='binary')
    accuracy = accuracy_score(labels, predictions)
    
    return {
        'accuracy': accuracy,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

class TrainingProgressCallback(TrainerCallback):
    """Custom callback to track training progress"""
    
    def on_train_begin(self, args, state, control, **kwargs):
        logger.info("🚀 Training started!")
    
    def on_epoch_begin(self, args, state, control, **kwargs):
        logger.info(f"📚 Starting epoch {int(state.epoch) + 1}/{args.num_train_epochs}")
    
    def on_step_end(self, args, state, control, **kwargs):
        if state.global_step % 50 == 0:
            logger.info(f"   Step {state.global_step}: Training in progress...")
    
    def on_evaluate(self, args, state, control, logs=None, **kwargs):
        if logs:
            logger.info(f"📊 Evaluation - F1: {logs.get('eval_f1', 0):.3f}, Accuracy: {logs.get('eval_accuracy', 0):.3f}")

def load_balanced_data(max_samples=3000, seed=42):
    """Load balanced dataset with retry logic"""
    dataset_path = Path("DiverseVul Dataset/diversevul_20230702.json")
    
    logger.info(f"📊 Loading balanced data (max {max_samples} samples)...")
    
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    
    vulnerable = []
    safe = []
    target_per_class = max_samples // 2
    
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if len(vulnerable) >= target_per_class and len(safe) >= target_per_class:
                    break
                    
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        code = item.get('func', '')
                        target = int(item.get('target', 0))
                        
                        # Filter reasonable code length
                        if 100 <= len(code) <= 3000:  # Reasonable range
                            if target == 1 and len(vulnerable) < target_per_class:
                                vulnerable.append(code)
                            elif target == 0 and len(safe) < target_per_class:
                                safe.append(code)
                                
                    except json.JSONDecodeError:
                        continue
                        
                if i % 20000 == 0 and i > 0:
                    logger.info(f"   Processed {i:,} lines, found {len(vulnerable)} vuln, {len(safe)} safe")
    
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        raise
    
    # Combine and create labels
    texts = vulnerable + safe
    labels = [1] * len(vulnerable) + [0] * len(safe)
    
    logger.info(f"✅ Dataset loaded: {len(vulnerable)} vulnerable, {len(safe)} safe samples")
    
    return texts, labels

def setup_model_with_retry(model_name="microsoft/codebert-base", max_retries=3):
    """Setup model with retry logic for network issues"""
    
    for attempt in range(max_retries):
        try:
            logger.info(f"🔄 Loading model (attempt {attempt + 1}/{max_retries}): {model_name}")
            
            # Set environment variables for better downloading
            os.environ['HF_HUB_DISABLE_SYMLINKS_WARNING'] = '1'
            os.environ['TRANSFORMERS_CACHE'] = str(Path.home() / '.cache' / 'transformers')
            
            # Load tokenizer first
            logger.info("   Loading tokenizer...")
            tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                resume_download=True,
                force_download=False
            )
            
            # Load model
            logger.info("   Loading model...")
            model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2,
                problem_type="single_label_classification",
                resume_download=True,
                force_download=False
            )
            
            logger.info("✅ Model and tokenizer loaded successfully!")
            return tokenizer, model
            
        except Exception as e:
            logger.error(f"❌ Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 30  # Exponential backoff
                logger.info(f"⏳ Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
            else:
                logger.error("❌ All retry attempts failed!")
                raise

def main():
    print("🛡️  CODEGUARDIAN ROBUST ML TRAINING")
    print("=" * 60)
    
    # Check device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"🖥️  Using device: {device}")
    
    try:
        # Load balanced data
        texts, labels = load_balanced_data(max_samples=3000)  # Increased sample size
        
        # Split data
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        logger.info(f"📚 Training samples: {len(train_texts)}, Validation: {len(val_texts)}")
        
        # Setup model with retry
        tokenizer, model = setup_model_with_retry()
        
        # Create datasets
        logger.info("🔧 Creating datasets...")
        train_dataset = RobustDataset(train_texts, train_labels, tokenizer)
        val_dataset = RobustDataset(val_texts, val_labels, tokenizer)
        
        # Training configuration
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = f"models/codebert_vulnerability_{timestamp}"
        
        logger.info(f"📁 Output directory: {output_dir}")
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=4,
            per_device_eval_batch_size=8,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir=f'{output_dir}/logs',
            logging_steps=50,
            eval_strategy="steps",  # Updated parameter name
            eval_steps=200,
            save_strategy="steps", 
            save_steps=400,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            report_to=None,
            dataloader_num_workers=0,
            remove_unused_columns=False,
            push_to_hub=False,
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
            callbacks=[
                EarlyStoppingCallback(early_stopping_patience=3),
                TrainingProgressCallback()
            ]
        )
        
        # Start training
        logger.info("🚀 Starting training process...")
        print("\n" + "="*60)
        print("🎯 TRAINING IN PROGRESS")
        print("="*60)
        
        start_time = time.time()
        trainer.train()
        training_time = time.time() - start_time
        
        # Evaluate
        logger.info("📊 Running final evaluation...")
        results = trainer.evaluate()
        
        # Display results
        print("\n" + "="*60)
        print("🏆 TRAINING COMPLETED SUCCESSFULLY!")
        print("="*60)
        print(f"⏱️  Training Time: {training_time/60:.1f} minutes")
        print(f"🎯 Final Results:")
        print(f"   📈 Accuracy:  {results['eval_accuracy']:.3f}")
        print(f"   🎲 F1-Score:  {results['eval_f1']:.3f}")
        print(f"   📊 Precision: {results['eval_precision']:.3f}")
        print(f"   📋 Recall:    {results['eval_recall']:.3f}")
        
        # Save the model
        logger.info("💾 Saving final model...")
        trainer.save_model()
        tokenizer.save_pretrained(output_dir)
        
        # Save training summary
        summary = {
            'timestamp': timestamp,
            'training_time_minutes': training_time / 60,
            'training_samples': len(train_texts),
            'validation_samples': len(val_texts),
            'results': results,
            'model_path': output_dir,
            'device': str(device)
        }
        
        with open(f"{output_dir}/training_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n✅ Model successfully saved to: {output_dir}")
        print(f"🔗 Ready for hybrid detection integration!")
        
        return output_dir
        
    except KeyboardInterrupt:
        logger.info("⚠️  Training interrupted by user")
        return None
    except Exception as e:
        logger.error(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    model_path = main()
    if model_path:
        print(f"\n🎉 SUCCESS: Model ready at {model_path}")
    else:
        print("\n❌ Training failed or was interrupted")