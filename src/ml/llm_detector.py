"""LLM-based vulnerability detection using fine-tuned CodeBERT."""

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import TrainingArguments, Trainer
import pandas as pd
from datasets import Dataset

class LLMVulnDetector:
    def __init__(self, model_name="microsoft/codebert-base"):
        self.model_name = model_name
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = None
        
    def prepare_training_data(self, vulnerable_snippets, safe_snippets):
        """Prepare training dataset from code snippets."""
        data = []
        
        # Vulnerable examples (label=1)
        for snippet in vulnerable_snippets:
            data.append({
                "code": snippet,
                "label": 1,
                "text": f"<code>{snippet}</code>"
            })
            
        # Safe examples (label=0)  
        for snippet in safe_snippets:
            data.append({
                "code": snippet,
                "label": 0,
                "text": f"<code>{snippet}</code>"
            })
            
        return Dataset.from_pandas(pd.DataFrame(data))
    
    def tokenize_data(self, examples):
        """Tokenize code snippets for BERT."""
        return self.tokenizer(
            examples["text"],
            truncation=True,
            padding=True,
            max_length=512
        )
    
    def fine_tune(self, train_dataset, val_dataset):
        """Fine-tune CodeBERT for vulnerability detection."""
        
        # Load pre-trained model
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=2
        )
        
        # Tokenize datasets
        train_dataset = train_dataset.map(self.tokenize_data, batched=True)
        val_dataset = val_dataset.map(self.tokenize_data, batched=True)
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir="./models/codebert-vuln-detector",
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir="./logs",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
        )
        
        # Fine-tune
        trainer.train()
        
        # Save model
        self.model.save_pretrained("./models/codebert-vuln-detector")
        self.tokenizer.save_pretrained("./models/codebert-vuln-detector")
        
    def predict_vulnerability(self, code_snippet):
        """Predict if code snippet contains vulnerability."""
        if not self.model:
            self.model = AutoModelForSequenceClassification.from_pretrained(
                "./models/codebert-vuln-detector"
            )
            
        inputs = self.tokenizer(
            f"<code>{code_snippet}</code>",
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        return {
            "is_vulnerable": predictions[0][1].item() > 0.5,
            "confidence": predictions[0][1].item(),
            "safe_score": predictions[0][0].item()
        }

# Example usage for training
if __name__ == "__main__":
    detector = LLMVulnDetector()
    
    # Load training data from your datasets
    vulnerable_code = [
        "String sql = \"SELECT * FROM users WHERE id = \" + userId;",
        "Runtime.getRuntime().exec(userInput);",
        "response.sendRedirect(request.getParameter(\"url\"));"
    ]
    
    safe_code = [
        "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");",
        "ProcessBuilder pb = new ProcessBuilder(Arrays.asList(\"ls\", \"-la\"));",
        "if (isValidUrl(url)) response.sendRedirect(url);"
    ]
    
    # Prepare and train
    train_data = detector.prepare_training_data(vulnerable_code, safe_code)
    val_data = detector.prepare_training_data(vulnerable_code[:2], safe_code[:2])
    
    detector.fine_tune(train_data, val_data)
    
    # Test prediction
    result = detector.predict_vulnerability("String query = \"SELECT * FROM \" + table;")
    print(f"Vulnerability detected: {result}")
