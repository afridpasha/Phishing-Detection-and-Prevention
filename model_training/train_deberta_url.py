from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from datasets import load_dataset, Dataset
import pandas as pd
import torch
import os

def train_deberta_url():
    """Fine-tune DeBERTa-v3 for URL classification"""
    print("Training DeBERTa-v3 URL Classifier...")
    
    dataset_path = 'datasets/url/combined_urls.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        return
    
    # Load data
    df = pd.read_csv(dataset_path)
    train_df = df.sample(frac=0.8, random_state=42)
    val_df = df.drop(train_df.index)
    
    # Create datasets
    train_dataset = Dataset.from_pandas(train_df[['url', 'label']].rename(columns={'url': 'text'}))
    val_dataset = Dataset.from_pandas(val_df[['url', 'label']].rename(columns={'url': 'text'}))
    
    # Load model and tokenizer
    model_name = 'microsoft/deberta-v3-base'
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    def tokenize_function(examples):
        return tokenizer(examples['text'], padding='max_length', truncation=True, max_length=128)
    
    train_dataset = train_dataset.map(tokenize_function, batched=True)
    val_dataset = val_dataset.map(tokenize_function, batched=True)
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir='models/url/deberta_url',
        num_train_epochs=5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        warmup_ratio=0.1,
        weight_decay=0.01,
        learning_rate=2e-5,
        logging_dir='./logs',
        logging_steps=500,
        evaluation_strategy='steps',
        eval_steps=500,
        save_strategy='steps',
        save_steps=500,
        load_best_model_at_end=True,
    )
    
    # Train
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )
    
    trainer.train()
    trainer.save_model('models/url/deberta_url')
    tokenizer.save_pretrained('models/url/deberta_url')
    print("Training complete!")

if __name__ == '__main__':
    train_deberta_url()
