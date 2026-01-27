"""
GNN Model Training - Domain Relationship Analysis
Trains Graph Neural Network on domain networks
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GCNConv, global_mean_pool
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("GNN MODEL TRAINER - Domain Relationship Analysis")
print("="*80)

# Generate synthetic domain network dataset
print("\n[*] Generating domain network dataset...")

def generate_domain_features():
    """Generate random domain features"""
    return {
        'domain_age': np.random.randint(0, 3650),  # days
        'ssl_valid': np.random.choice([0, 1]),
        'dns_records': np.random.randint(1, 10),
        'whois_privacy': np.random.choice([0, 1]),
        'subdomain_count': np.random.randint(0, 5),
        'ip_reputation': np.random.uniform(0, 1),
        'registrar_reputation': np.random.uniform(0, 1),
        'tld_suspicious': np.random.choice([0, 1]),
    }

def create_domain_graph(is_phishing=True):
    """Create a domain relationship graph"""
    num_nodes = np.random.randint(5, 15)  # Number of related domains
    
    # Node features (8 features per domain)
    node_features = []
    for _ in range(num_nodes):
        features = generate_domain_features()
        if is_phishing:
            # Phishing domains have suspicious patterns
            features['domain_age'] = np.random.randint(0, 90)  # Very new
            features['ssl_valid'] = 0  # No SSL
            features['whois_privacy'] = 1  # Hidden WHOIS
            features['tld_suspicious'] = 1  # Suspicious TLD
        else:
            # Legitimate domains
            features['domain_age'] = np.random.randint(365, 3650)  # Older
            features['ssl_valid'] = 1  # Valid SSL
            features['whois_privacy'] = 0  # Public WHOIS
            features['tld_suspicious'] = 0  # Normal TLD
        
        node_features.append(list(features.values()))
    
    x = torch.tensor(node_features, dtype=torch.float)
    
    # Edge connections (domain relationships)
    edge_index = []
    for i in range(num_nodes):
        for j in range(i+1, num_nodes):
            if np.random.random() > 0.5:  # 50% connection probability
                edge_index.append([i, j])
                edge_index.append([j, i])  # Undirected graph
    
    if len(edge_index) == 0:
        # Ensure at least one edge
        edge_index = [[0, 1], [1, 0]]
    
    edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    
    # Label
    y = torch.tensor([1 if is_phishing else 0], dtype=torch.long)
    
    return Data(x=x, edge_index=edge_index, y=y)

# Generate dataset
print("[*] Generating graph data...")
graphs = []

for _ in range(400):
    graphs.append(create_domain_graph(is_phishing=True))

for _ in range(400):
    graphs.append(create_domain_graph(is_phishing=False))

print(f"[+] Generated {len(graphs)} domain graphs")
print(f"    - Phishing: 400")
print(f"    - Legitimate: 400")

# Split data
train_graphs, test_graphs = train_test_split(graphs, test_size=0.2, random_state=42)

print(f"\n[*] Split dataset:")
print(f"    - Training: {len(train_graphs)}")
print(f"    - Testing: {len(test_graphs)}")

train_loader = DataLoader(train_graphs, batch_size=32, shuffle=True)
test_loader = DataLoader(test_graphs, batch_size=32)

# GNN Model
class GNNModel(nn.Module):
    def __init__(self, num_features, hidden_dim=64, num_classes=2):
        super(GNNModel, self).__init__()
        self.conv1 = GCNConv(num_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        self.fc = nn.Linear(hidden_dim, num_classes)
    
    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.5, training=self.training)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.5, training=self.training)
        
        x = self.conv3(x, edge_index)
        x = F.relu(x)
        
        # Global pooling
        x = global_mean_pool(x, batch)
        
        x = self.fc(x)
        return x

# Initialize model
print("\n[*] Initializing GNN model...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[+] Using device: {device}")

model = GNNModel(num_features=8, hidden_dim=64, num_classes=2)
model.to(device)

# Loss and optimizer
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Training
print("\n[*] Training model...")
epochs = 50

for epoch in range(epochs):
    model.train()
    total_loss = 0
    
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()
        
        output = model(data)
        loss = criterion(output, data.y)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
    
    avg_loss = total_loss / len(train_loader)
    if (epoch + 1) % 10 == 0:
        print(f"[{epoch+1}/{epochs}] Loss: {avg_loss:.4f}")

# Evaluation
print("\n[*] Evaluating model...")
model.eval()
predictions = []
true_labels = []

with torch.no_grad():
    for data in test_loader:
        data = data.to(device)
        output = model(data)
        pred = output.argmax(dim=1)
        
        predictions.extend(pred.cpu().numpy())
        true_labels.extend(data.y.cpu().numpy())

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
torch.save(model.state_dict(), 'models/gnn_model.pth')
print("[+] Saved: models/gnn_model.pth")

# Save model architecture info
model_info = {
    'num_features': 8,
    'hidden_dim': 64,
    'num_classes': 2
}
torch.save(model_info, 'models/gnn_model_info.pth')
print("[+] Saved: models/gnn_model_info.pth")

print("\n" + "="*80)
print("[+] GNN Model training completed!")
print("="*80)
