from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from datasets import Dataset
import pandas as pd
import os

def train_securebert_sms():
    """Fine-tune SecureBERT for SMS smishing detection"""
    print("Training SecureBERT SMS Classifier...")
    
    dataset_path = 'datasets/sms/smishing_collection.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        return
    
    df = pd.read_csv(dataset_path)
    train_df = df.sample(frac=0.8, random_state=42)
    val_df = df.drop(train_df.index)
    
    train_dataset = Dataset.from_pandas(train_df[['message', 'label']].rename(columns={'message': 'text'}))
    val_dataset = Dataset.from_pandas(val_df[['message', 'label']].rename(columns={'message': 'text'}))
    
    model_name = 'ehsanaghaei/SecureBERT'
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    def tokenize_function(examples):
        return tokenizer(examples['text'], padding='max_length', truncation=True, max_length=512)
    
    train_dataset = train_dataset.map(tokenize_function, batched=True)
    val_dataset = val_dataset.map(tokenize_function, batched=True)
    
    training_args = TrainingArguments(
        output_dir='models/sms/securebert_sms',
        num_train_epochs=10,
        per_device_train_batch_size=32,
        learning_rate=3e-5,
        weight_decay=0.01,
        logging_steps=100,
        evaluation_strategy='epoch',
        save_strategy='epoch',
        load_best_model_at_end=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )
    
    trainer.train()
    trainer.save_model('models/sms/securebert_sms')
    tokenizer.save_pretrained('models/sms/securebert_sms')
    print("Training complete!")

if __name__ == '__main__':
    train_securebert_sms()
