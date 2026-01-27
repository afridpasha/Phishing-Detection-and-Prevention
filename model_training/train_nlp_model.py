"""
NLP Model Training - Email/SMS Phishing Detection
Trains BERT-based model on text data
"""

import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertForSequenceClassification, AdamW
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("NLP MODEL TRAINER - Email/SMS Phishing Detection")
print("="*80)

# Generate synthetic email/SMS dataset
print("\n[*] Generating NLP training dataset...")

phishing_emails = [
    # Urgency tactics
    "URGENT: Your account will be suspended in 24 hours. Verify now!",
    "IMMEDIATE ACTION REQUIRED: Confirm your identity to avoid account closure",
    "Your PayPal account has been limited. Click here to restore access",
    "Security Alert: Unusual activity detected. Verify your account immediately",
    "Your package delivery failed. Update shipping details now",
    
    # Financial threats
    "Your bank account will be closed. Confirm your details to prevent this",
    "Unauthorized transaction detected. Click to cancel the payment",
    "Your credit card has been charged $999. Dispute this charge now",
    "Tax refund of $1,500 waiting. Claim within 48 hours or lose it",
    "You've won $10,000! Click here to claim your prize",
    
    # Credential harvesting
    "Your password will expire today. Reset it now to continue access",
    "Microsoft account security: Verify your identity to unlock account",
    "Amazon: Your order #12345 requires payment confirmation",
    "Netflix: Your subscription has expired. Update payment method",
    "Apple ID: Suspicious login attempt detected. Secure your account",
    
    # Authority impersonation
    "IRS: You owe back taxes. Pay immediately to avoid legal action",
    "FBI: Your computer has been locked due to illegal activity",
    "Social Security Administration: Your SSN has been suspended",
    "Court Notice: You have an outstanding warrant. Click for details",
    "Police Department: Traffic violation fine. Pay now to avoid arrest",
]

legitimate_emails = [
    # Normal business
    "Thank you for your purchase. Your order will arrive in 3-5 days",
    "Your monthly statement is now available. View it in your account",
    "Meeting reminder: Team sync tomorrow at 10 AM",
    "Your subscription renewal is coming up next month",
    "Welcome to our newsletter! Here are this week's updates",
    
    # Transactional
    "Your order #67890 has been shipped. Track your package here",
    "Receipt for your recent purchase at Store Name",
    "Your appointment is confirmed for next Tuesday at 2 PM",
    "Password reset successful. You can now log in with your new password",
    "Your support ticket #12345 has been resolved",
    
    # Informational
    "New features available in your account. Check them out",
    "System maintenance scheduled for this weekend",
    "Your feedback helps us improve. Take our quick survey",
    "Monthly report: Your account summary for January",
    "Reminder: Your free trial ends in 7 days",
    
    # Social
    "John Doe sent you a connection request on LinkedIn",
    "You have 5 new notifications from your social network",
    "Your friend tagged you in a photo",
    "Happy birthday! Here's a special offer for you",
    "Your post received 50 likes and 10 comments",
]

# Expand dataset
phishing_expanded = phishing_emails * 200  # 4,000 samples
legitimate_expanded = legitimate_emails * 200  # 4,000 samples

# Create DataFrame
data = []
for text in phishing_expanded:
    data.append({'text': text, 'label': 1})
for text in legitimate_expanded:
    data.append({'text': text, 'label': 0})

df = pd.DataFrame(data)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"[+] Generated {len(df)} samples")
print(f"    - Phishing: {(df['label']==1).sum()}")
print(f"    - Legitimate: {(df['label']==0).sum()}")

# Save dataset
df.to_csv('datasets/EMAIL_SMS_PHISHING_DATASET.csv', index=False)
print("[+] Saved: datasets/EMAIL_SMS_PHISHING_DATASET.csv")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    df['text'].values, df['label'].values, test_size=0.2, random_state=42, stratify=df['label']
)

print(f"\n[*] Split dataset:")
print(f"    - Training: {len(X_train)}")
print(f"    - Testing: {len(X_test)}")

# Initialize BERT tokenizer
print("\n[*] Loading BERT tokenizer...")
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

# Tokenize
print("[*] Tokenizing text...")
train_encodings = tokenizer(list(X_train), truncation=True, padding=True, max_length=128)
test_encodings = tokenizer(list(X_test), truncation=True, padding=True, max_length=128)

# Dataset class
class PhishingDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels
    
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

train_dataset = PhishingDataset(train_encodings, y_train)
test_dataset = PhishingDataset(test_encodings, y_test)

# DataLoaders
train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=16)

# Initialize model
print("\n[*] Initializing BERT model...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[+] Using device: {device}")

model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
model.to(device)

# Optimizer
optimizer = AdamW(model.parameters(), lr=2e-5)

# Training
print("\n[*] Training model...")
epochs = 3

for epoch in range(epochs):
    model.train()
    total_loss = 0
    
    for batch in train_loader:
        optimizer.zero_grad()
        
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)
        
        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
        loss = outputs.loss
        total_loss += loss.item()
        
        loss.backward()
        optimizer.step()
    
    avg_loss = total_loss / len(train_loader)
    print(f"[{epoch+1}/{epochs}] Loss: {avg_loss:.4f}")

# Evaluation
print("\n[*] Evaluating model...")
model.eval()
predictions = []
true_labels = []

with torch.no_grad():
    for batch in test_loader:
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)
        
        outputs = model(input_ids, attention_mask=attention_mask)
        preds = torch.argmax(outputs.logits, dim=1)
        
        predictions.extend(preds.cpu().numpy())
        true_labels.extend(labels.cpu().numpy())

# Metrics
acc = accuracy_score(true_labels, predictions)
prec = precision_score(true_labels, predictions)
rec = recall_score(true_labels, predictions)
f1 = f1_score(true_labels, predictions)

print("\n" + "="*80)
print("RESULTS")
print("="*80)
print(f"\nAccuracy:  {acc:.4f} ({acc*100:.2f}%)")
print(f"Precision: {prec:.4f} ({prec*100:.2f}%)")
print(f"Recall:    {rec:.4f} ({rec*100:.2f}%)")
print(f"F1-Score:  {f1:.4f}")

print("\nClassification Report:")
print(classification_report(true_labels, predictions, target_names=['Legitimate', 'Phishing']))

# Save model
print("\n[*] Saving model...")
model.save_pretrained('models/nlp_bert_model')
tokenizer.save_pretrained('models/nlp_bert_model')
print("[+] Saved: models/nlp_bert_model/")

print("\n" + "="*80)
print("[+] NLP Model training completed!")
print("="*80)
