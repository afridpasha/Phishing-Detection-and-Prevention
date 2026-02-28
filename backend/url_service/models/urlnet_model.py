import torch
import torch.nn as nn
import numpy as np
from typing import Tuple

class URLNet(nn.Module):
    def __init__(self, char_vocab_size=128, word_vocab_size=50000, 
                 char_embed_dim=32, word_embed_dim=64):
        super(URLNet, self).__init__()
        
        # Character branch
        self.char_embedding = nn.Embedding(char_vocab_size, char_embed_dim)
        self.char_conv1 = nn.Conv1d(char_embed_dim, 256, kernel_size=3, padding=1)
        self.char_conv2 = nn.Conv1d(char_embed_dim, 256, kernel_size=5, padding=2)
        self.char_pool = nn.MaxPool1d(2)
        self.char_dropout = nn.Dropout(0.3)
        self.char_fc = nn.Linear(256, 512)
        
        # Word branch
        self.word_embedding = nn.Embedding(word_vocab_size, word_embed_dim)
        self.word_lstm = nn.LSTM(word_embed_dim, 256, num_layers=2, 
                                 bidirectional=True, batch_first=True)
        self.word_fc = nn.Linear(512, 512)
        
        # Fusion
        self.fusion_fc1 = nn.Linear(1024, 512)
        self.fusion_dropout = nn.Dropout(0.5)
        self.fusion_fc2 = nn.Linear(512, 256)
        self.output = nn.Linear(256, 1)
        
    def forward(self, char_input, word_input):
        # Character branch
        char_embed = self.char_embedding(char_input).transpose(1, 2)
        char_conv1_out = torch.relu(self.char_conv1(char_embed))
        char_conv2_out = torch.relu(self.char_conv2(char_embed))
        char_concat = torch.cat([char_conv1_out, char_conv2_out], dim=1)
        char_pooled = self.char_pool(char_concat)
        char_pooled = torch.mean(char_pooled, dim=2)
        char_out = torch.relu(self.char_fc(char_pooled[:, :256]))
        
        # Word branch
        word_embed = self.word_embedding(word_input)
        word_lstm_out, _ = self.word_lstm(word_embed)
        word_out = torch.mean(word_lstm_out, dim=1)
        word_out = torch.relu(self.word_fc(word_out))
        
        # Fusion
        fused = torch.cat([char_out, word_out], dim=1)
        fused = torch.relu(self.fusion_fc1(fused))
        fused = self.fusion_dropout(fused)
        fused = torch.relu(self.fusion_fc2(fused))
        output = torch.sigmoid(self.output(fused))
        
        return output

class URLNetInference:
    def __init__(self, model_path: str, device='cpu'):
        self.device = device
        self.model = URLNet()
        self.model.load_state_dict(torch.load(model_path, map_location=device))
        self.model.to(device)
        self.model.eval()
        
        self.char_vocab = {chr(i): i for i in range(128)}
        self.max_char_len = 200
        self.max_word_len = 30
    
    def tokenize_chars(self, url: str) -> torch.Tensor:
        """Tokenize URL as character sequence"""
        tokens = [self.char_vocab.get(c, 0) for c in url[:self.max_char_len]]
        tokens += [0] * (self.max_char_len - len(tokens))
        return torch.tensor([tokens], dtype=torch.long).to(self.device)
    
    def tokenize_words(self, url: str) -> torch.Tensor:
        """Tokenize URL as word sequence"""
        import re
        words = re.split(r'[./\-_?=&]', url)
        tokens = [hash(w) % 50000 for w in words[:self.max_word_len]]
        tokens += [0] * (self.max_word_len - len(tokens))
        return torch.tensor([tokens], dtype=torch.long).to(self.device)
    
    def predict(self, url: str) -> float:
        """Predict phishing probability"""
        with torch.no_grad():
            char_input = self.tokenize_chars(url)
            word_input = self.tokenize_words(url)
            score = self.model(char_input, word_input).item()
        return score
