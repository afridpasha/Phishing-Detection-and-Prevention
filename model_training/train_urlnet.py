import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import pandas as pd
from backend.url_service.models.urlnet_model import URLNet
import os

class URLDataset(Dataset):
    def __init__(self, csv_path, max_char_len=200, max_word_len=30):
        self.data = pd.read_csv(csv_path)
        self.max_char_len = max_char_len
        self.max_word_len = max_word_len
        self.char_vocab = {chr(i): i for i in range(128)}
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        url = self.data.iloc[idx]['url']
        label = self.data.iloc[idx]['label']
        
        # Tokenize characters
        char_tokens = [self.char_vocab.get(c, 0) for c in url[:self.max_char_len]]
        char_tokens += [0] * (self.max_char_len - len(char_tokens))
        
        # Tokenize words
        import re
        words = re.split(r'[./\-_?=&]', url)
        word_tokens = [hash(w) % 50000 for w in words[:self.max_word_len]]
        word_tokens += [0] * (self.max_word_len - len(word_tokens))
        
        return (
            torch.tensor(char_tokens, dtype=torch.long),
            torch.tensor(word_tokens, dtype=torch.long),
            torch.tensor(label, dtype=torch.float)
        )

def train_urlnet():
    """Train URLNet model"""
    print("Training URLNet...")
    
    # Check if dataset exists
    dataset_path = 'datasets/url/combined_urls.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        print("Please prepare dataset with columns: url, label")
        return
    
    # Hyperparameters
    batch_size = 512
    epochs = 50
    learning_rate = 1e-3
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    # Load dataset
    dataset = URLDataset(dataset_path)
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Initialize model
    model = URLNet().to(device)
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3)
    
    # Training loop
    best_val_loss = float('inf')
    patience_counter = 0
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        
        for char_input, word_input, labels in train_loader:
            char_input = char_input.to(device)
            word_input = word_input.to(device)
            labels = labels.to(device).unsqueeze(1)
            
            optimizer.zero_grad()
            outputs = model(char_input, word_input)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
        
        # Validation
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for char_input, word_input, labels in val_loader:
                char_input = char_input.to(device)
                word_input = word_input.to(device)
                labels = labels.to(device).unsqueeze(1)
                
                outputs = model(char_input, word_input)
                loss = criterion(outputs, labels)
                val_loss += loss.item()
                
                predicted = (outputs > 0.5).float()
                correct += (predicted == labels).sum().item()
                total += labels.size(0)
        
        train_loss /= len(train_loader)
        val_loss /= len(val_loader)
        accuracy = correct / total
        
        print(f"Epoch {epoch+1}/{epochs} - Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, Accuracy: {accuracy:.4f}")
        
        scheduler.step(val_loss)
        
        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), 'models/url/urlnet_model.pt')
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 5:
                print("Early stopping triggered")
                break
    
    print("Training complete!")

if __name__ == '__main__':
    train_urlnet()
