"""
CNN Model Training - Visual Phishing Detection
Trains ResNet-50 on webpage screenshots
"""

import numpy as np
import torch
import torch.nn as nn
import torchvision.models as models
import torchvision.transforms as transforms
from torch.utils.data import Dataset, DataLoader
from PIL import Image, ImageDraw, ImageFont
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import os
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("CNN MODEL TRAINER - Visual Phishing Detection")
print("="*80)

# Generate synthetic webpage screenshots
print("\n[*] Generating synthetic webpage images...")

def create_fake_login_page(brand, is_phishing=True):
    """Generate synthetic login page image"""
    img = Image.new('RGB', (800, 600), color='white')
    draw = ImageDraw.Draw(img)
    
    # Title
    if is_phishing:
        title = f"Verify Your {brand} Account"
        draw.rectangle([50, 50, 750, 100], fill='red')
    else:
        title = f"{brand} Login"
        draw.rectangle([50, 50, 750, 100], fill='blue')
    
    # Login form
    draw.rectangle([250, 200, 550, 250], outline='black', width=2)  # Username
    draw.rectangle([250, 270, 550, 320], outline='black', width=2)  # Password
    draw.rectangle([300, 350, 500, 390], fill='green')  # Button
    
    # Suspicious elements for phishing
    if is_phishing:
        draw.rectangle([100, 500, 700, 550], fill='yellow')  # Warning banner
        draw.text((120, 515), "URGENT: Verify within 24 hours!", fill='red')
    
    return img

def create_legitimate_page(brand):
    """Generate legitimate page"""
    img = Image.new('RGB', (800, 600), color='#f5f5f5')
    draw = ImageDraw.Draw(img)
    
    # Header
    draw.rectangle([0, 0, 800, 80], fill='#0066cc')
    draw.text((350, 30), brand, fill='white')
    
    # Content area
    draw.rectangle([200, 150, 600, 450], fill='white', outline='#ccc', width=2)
    draw.rectangle([250, 200, 550, 240], outline='#999', width=1)
    draw.rectangle([250, 260, 550, 300], outline='#999', width=1)
    draw.rectangle([300, 340, 500, 380], fill='#0066cc')
    
    return img

# Create dataset directory
os.makedirs('datasets/webpage_images', exist_ok=True)
os.makedirs('datasets/webpage_images/phishing', exist_ok=True)
os.makedirs('datasets/webpage_images/legitimate', exist_ok=True)

brands = ['PayPal', 'Amazon', 'Microsoft', 'Google', 'Facebook', 'Apple', 'Netflix', 'Bank']

# Generate images
print("[*] Generating phishing images...")
for i in range(500):
    brand = brands[i % len(brands)]
    img = create_fake_login_page(brand, is_phishing=True)
    img.save(f'datasets/webpage_images/phishing/phish_{i}.png')

print("[*] Generating legitimate images...")
for i in range(500):
    brand = brands[i % len(brands)]
    img = create_legitimate_page(brand)
    img.save(f'datasets/webpage_images/legitimate/legit_{i}.png')

print(f"[+] Generated 1000 images (500 phishing, 500 legitimate)")

# Dataset class
class WebpageDataset(Dataset):
    def __init__(self, image_paths, labels, transform=None):
        self.image_paths = image_paths
        self.labels = labels
        self.transform = transform
    
    def __len__(self):
        return len(self.image_paths)
    
    def __getitem__(self, idx):
        img = Image.open(self.image_paths[idx]).convert('RGB')
        if self.transform:
            img = self.transform(img)
        return img, self.labels[idx]

# Collect image paths
phishing_images = [f'datasets/webpage_images/phishing/phish_{i}.png' for i in range(500)]
legitimate_images = [f'datasets/webpage_images/legitimate/legit_{i}.png' for i in range(500)]

all_images = phishing_images + legitimate_images
all_labels = [1] * 500 + [0] * 500

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    all_images, all_labels, test_size=0.2, random_state=42, stratify=all_labels
)

print(f"\n[*] Split dataset:")
print(f"    - Training: {len(X_train)}")
print(f"    - Testing: {len(X_test)}")

# Transforms
transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
])

train_dataset = WebpageDataset(X_train, y_train, transform=transform)
test_dataset = WebpageDataset(X_test, y_test, transform=transform)

train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=32)

# Initialize ResNet-50
print("\n[*] Initializing ResNet-50 model...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[+] Using device: {device}")

model = models.resnet50(pretrained=True)
model.fc = nn.Linear(model.fc.in_features, 2)  # Binary classification
model.to(device)

# Loss and optimizer
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Training
print("\n[*] Training model...")
epochs = 5

for epoch in range(epochs):
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    for images, labels in train_loader:
        images, labels = images.to(device), labels.to(device)
        
        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()
    
    acc = correct / total
    avg_loss = total_loss / len(train_loader)
    print(f"[{epoch+1}/{epochs}] Loss: {avg_loss:.4f}, Accuracy: {acc:.4f}")

# Evaluation
print("\n[*] Evaluating model...")
model.eval()
predictions = []
true_labels = []

with torch.no_grad():
    for images, labels in test_loader:
        images, labels = images.to(device), labels.to(device)
        outputs = model(images)
        _, predicted = torch.max(outputs.data, 1)
        
        predictions.extend(predicted.cpu().numpy())
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

# Save model
print("\n[*] Saving model...")
torch.save(model.state_dict(), 'models/cnn_resnet50_model.pth')
print("[+] Saved: models/cnn_resnet50_model.pth")

print("\n" + "="*80)
print("[+] CNN Model training completed!")
print("="*80)
