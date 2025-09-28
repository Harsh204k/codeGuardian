#!/usr/bin/env python3
"""
Quick ML Training Demo - Hybrid Vulnerability Detection
Train CodeBERT on a small subset first
"""

import json
import torch
import logging
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuickDataset(torch.utils.data.Dataset):
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

def load_sample_data(max_samples=1000):
    """Load a small sample for quick training"""
    dataset_path = Path("DiverseVul Dataset/diversevul_20230702.json")
    
    logger.info("Loading sample data for quick training...")
    
    vulnerable = []
    safe = []
    
    with open(dataset_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if len(vulnerable) >= max_samples//2 and len(safe) >= max_samples//2:
                break
                
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                    code = item.get('func', '')
                    target = int(item.get('target', 0))
                    
                    # Filter reasonable code length
                    if 100 <= len(code) <= 2000:
                        if target == 1 and len(vulnerable) < max_samples//2:
                            vulnerable.append(code)
                        elif target == 0 and len(safe) < max_samples//2:
                            safe.append(code)
                            
                except json.JSONDecodeError:
                    continue
                    
            if i % 10000 == 0:
                logger.info(f"Processed {i} lines, found {len(vulnerable)} vuln, {len(safe)} safe")
    
    # Combine and create labels
    texts = vulnerable + safe
    labels = [1] * len(vulnerable) + [0] * len(safe)
    
    logger.info(f"Sample dataset: {len(vulnerable)} vulnerable, {len(safe)} safe samples")
    
    return texts, labels

def main():
    print("🚀 QUICK ML TRAINING DEMO")
    print("=" * 50)
    
    # Check device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Using device: {device}")
    
    # Load sample data
    texts, labels = load_sample_data(max_samples=2000)  # Small sample for demo
    
    # Split data
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    logger.info(f"Training samples: {len(train_texts)}, Validation: {len(val_texts)}")
    
    # Initialize tokenizer and model
    model_name = "microsoft/codebert-base"
    logger.info(f"Loading {model_name}...")
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2,
        problem_type="single_label_classification"
    )
    
    # Create datasets
    train_dataset = QuickDataset(train_texts, train_labels, tokenizer)
    val_dataset = QuickDataset(val_texts, val_labels, tokenizer)
    
    # Training arguments
    output_dir = f"models/quick_codebert_{datetime.now().strftime('%Y%m%d_%H%M')}"
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=2,  # Quick training
        per_device_train_batch_size=4,  # Small batch
        per_device_eval_batch_size=8,
        warmup_steps=50,
        weight_decay=0.01,
        logging_dir=f'{output_dir}/logs',
        logging_steps=50,
        evaluation_strategy="steps",
        eval_steps=100,
        save_strategy="steps",
        save_steps=200,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        report_to=None,
        dataloader_num_workers=0,
    )
    
    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )
    
    # Train the model
    logger.info("Starting training...")
    trainer.train()
    
    # Evaluate
    logger.info("Evaluating model...")
    results = trainer.evaluate()
    
    print("\n🎯 TRAINING RESULTS:")
    print(f"Accuracy: {results['eval_accuracy']:.3f}")
    print(f"F1-Score: {results['eval_f1']:.3f}")
    print(f"Precision: {results['eval_precision']:.3f}")
    print(f"Recall: {results['eval_recall']:.3f}")
    
    # Save the model
    trainer.save_model()
    tokenizer.save_pretrained(output_dir)
    
    logger.info(f"Model saved to {output_dir}")
    
    print("\n✅ Quick training completed!")
    print(f"Model saved to: {output_dir}")

if __name__ == "__main__":
    main()