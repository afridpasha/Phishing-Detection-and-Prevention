"""
NLP Text Analysis Module - BERT/RoBERTa Implementation
Real-Time Phishing Detection System

This module implements transformer-based NLP models for semantic analysis
of email/SMS content, detecting phishing attempts through context understanding.
"""

import torch
import torch.nn as nn
from transformers import (
    BertTokenizer, BertModel,
    RobertaTokenizer, RobertaModel,
    AutoTokenizer, AutoModel
)
from typing import Dict, List, Tuple, Optional
import numpy as np
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NLPPhishingDetector(nn.Module):
    """
    Transformer-based NLP model for phishing detection
    
    Architecture:
    - Base: Pre-trained BERT/RoBERTa (12-layer transformer)
    - Fine-tuning layers: Dense(768→256→64)
    - Output: Sigmoid activation for binary classification
    - Regularization: Dropout(0.3), L2 regularization
    """
    
    def __init__(
        self,
        model_name: str = "bert-base-uncased",
        dropout_rate: float = 0.3,
        num_classes: int = 2,
        freeze_base: bool = False
    ):
        super(NLPPhishingDetector, self).__init__()
        
        self.model_name = model_name
        self.num_classes = num_classes
        
        # Load pre-trained transformer model
        logger.info(f"Loading pre-trained model: {model_name}")
        if "roberta" in model_name.lower():
            self.tokenizer = RobertaTokenizer.from_pretrained(model_name)
            self.transformer = RobertaModel.from_pretrained(model_name)
        elif "bert" in model_name.lower():
            self.tokenizer = BertTokenizer.from_pretrained(model_name)
            self.transformer = BertModel.from_pretrained(model_name)
        else:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.transformer = AutoModel.from_pretrained(model_name)
        
        # Freeze base model if specified
        if freeze_base:
            for param in self.transformer.parameters():
                param.requires_grad = False
        
        # Get hidden size from transformer
        hidden_size = self.transformer.config.hidden_size  # 768 for BERT-base
        
        # Classification head with 2 dense layers
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(64, num_classes)
        )
        
        # Sigmoid for binary classification confidence score
        self.sigmoid = nn.Sigmoid()
        
        logger.info(f"NLP Model initialized with {hidden_size}-dim embeddings")
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        return_embeddings: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the model
        
        Args:
            input_ids: Token IDs from tokenizer
            attention_mask: Attention mask for padding
            return_embeddings: Whether to return transformer embeddings
            
        Returns:
            Dictionary containing logits, probabilities, and optionally embeddings
        """
        # Get transformer outputs
        outputs = self.transformer(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=True
        )
        
        # Use [CLS] token representation (first token)
        cls_embedding = outputs.last_hidden_state[:, 0, :]
        
        # Classification
        logits = self.classifier(cls_embedding)
        probs = self.sigmoid(logits)
        
        result = {
            'logits': logits,
            'probabilities': probs,
            'prediction': torch.argmax(logits, dim=1)
        }
        
        if return_embeddings:
            result['embeddings'] = cls_embedding
        
        return result
    
    def preprocess_text(
        self,
        text: str,
        max_length: int = 512,
        padding: str = 'max_length',
        truncation: bool = True
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenize and preprocess text input
        
        Args:
            text: Input text to analyze
            max_length: Maximum sequence length
            padding: Padding strategy
            truncation: Whether to truncate long sequences
            
        Returns:
            Dictionary with input_ids and attention_mask
        """
        encoding = self.tokenizer(
            text,
            max_length=max_length,
            padding=padding,
            truncation=truncation,
            return_tensors='pt'
        )
        
        return encoding
    
    def analyze_email(
        self,
        subject: str,
        body: str,
        sender: Optional[str] = None,
        urls: Optional[List[str]] = None
    ) -> Dict[str, any]:
        """
        Analyze email content for phishing indicators
        
        Args:
            subject: Email subject line
            body: Email body content
            sender: Sender email address
            urls: List of URLs in email
            
        Returns:
            Analysis results with confidence score and features
        """
        # Combine email components
        email_text = f"Subject: {subject}\n\n{body}"
        
        if sender:
            email_text = f"From: {sender}\n" + email_text
        
        if urls:
            email_text += f"\n\nURLs: {' '.join(urls[:5])}"  # Limit to 5 URLs
        
        # Tokenize
        encoding = self.preprocess_text(email_text)
        
        # Set model to evaluation mode
        self.eval()
        
        with torch.no_grad():
            # Get predictions
            outputs = self.forward(
                input_ids=encoding['input_ids'],
                attention_mask=encoding['attention_mask'],
                return_embeddings=True
            )
            
            # Extract phishing probability (class 1)
            phishing_prob = outputs['probabilities'][0][1].item()
            prediction = outputs['prediction'][0].item()
            
        # Extract linguistic features
        features = self._extract_features(subject, body)
        
        return {
            'phishing_probability': phishing_prob,
            'is_phishing': prediction == 1,
            'confidence': max(outputs['probabilities'][0]).item(),
            'features': features,
            'timestamp': datetime.now().isoformat(),
            'model': self.model_name
        }
    
    def _extract_features(self, subject: str, body: str) -> Dict[str, any]:
        """
        Extract linguistic and semantic features
        
        Returns:
            Dictionary of extracted features
        """
        import re
        
        features = {}
        
        # Urgency keywords
        urgency_keywords = [
            'urgent', 'immediate', 'action required', 'verify', 'confirm',
            'suspended', 'expire', 'limited time', 'act now', 'within 24 hours'
        ]
        features['urgency_score'] = sum(
            1 for keyword in urgency_keywords 
            if keyword.lower() in subject.lower() or keyword.lower() in body.lower()
        ) / len(urgency_keywords)
        
        # Threat language
        threat_keywords = [
            'suspended', 'locked', 'unauthorized', 'security alert',
            'unusual activity', 'blocked', 'compromised'
        ]
        features['threat_score'] = sum(
            1 for keyword in threat_keywords
            if keyword.lower() in subject.lower() or keyword.lower() in body.lower()
        ) / len(threat_keywords)
        
        # Financial keywords
        financial_keywords = [
            'payment', 'bank', 'credit card', 'account', 'refund',
            'invoice', 'transfer', 'verify payment', 'update billing'
        ]
        features['financial_score'] = sum(
            1 for keyword in financial_keywords
            if keyword.lower() in subject.lower() or keyword.lower() in body.lower()
        ) / len(financial_keywords)
        
        # Generic greeting (phishing indicator)
        generic_greetings = ['dear customer', 'dear user', 'valued customer', 'dear member']
        features['generic_greeting'] = any(
            greeting in body.lower() for greeting in generic_greetings
        )
        
        # Spelling/grammar issues (simple heuristic)
        features['has_multiple_exclamations'] = '!!' in subject or '!!' in body
        features['all_caps_words'] = len(re.findall(r'\b[A-Z]{3,}\b', subject + ' ' + body))
        
        # Link count
        features['url_count'] = len(re.findall(r'http[s]?://\S+', body))
        
        return features
    
    def batch_analyze(
        self,
        texts: List[str],
        batch_size: int = 32
    ) -> List[Dict[str, any]]:
        """
        Analyze multiple texts in batches for efficiency
        
        Args:
            texts: List of text strings to analyze
            batch_size: Batch size for processing
            
        Returns:
            List of analysis results
        """
        results = []
        self.eval()
        
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i+batch_size]
            
            # Tokenize batch
            encodings = self.tokenizer(
                batch_texts,
                max_length=512,
                padding=True,
                truncation=True,
                return_tensors='pt'
            )
            
            with torch.no_grad():
                outputs = self.forward(
                    input_ids=encodings['input_ids'],
                    attention_mask=encodings['attention_mask']
                )
                
                probs = outputs['probabilities']
                predictions = outputs['prediction']
            
            # Process results
            for j, text in enumerate(batch_texts):
                results.append({
                    'text': text[:100],  # First 100 chars
                    'phishing_probability': probs[j][1].item(),
                    'is_phishing': predictions[j].item() == 1,
                    'confidence': max(probs[j]).item()
                })
        
        return results


class AdvancedFeatureExtractor:
    """
    Advanced feature extraction for NLP analysis
    Includes entity recognition, sentiment analysis, and contextual features
    """
    
    def __init__(self):
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
        except:
            logger.warning("spaCy model not found. Install with: python -m spacy download en_core_web_sm")
            self.nlp = None
    
    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities (brands, organizations, etc.)"""
        if not self.nlp:
            return {}
        
        doc = self.nlp(text)
        entities = {
            'organizations': [],
            'persons': [],
            'locations': [],
            'money': [],
            'dates': []
        }
        
        for ent in doc.ents:
            if ent.label_ == 'ORG':
                entities['organizations'].append(ent.text)
            elif ent.label_ == 'PERSON':
                entities['persons'].append(ent.text)
            elif ent.label_ == 'GPE':
                entities['locations'].append(ent.text)
            elif ent.label_ == 'MONEY':
                entities['money'].append(ent.text)
            elif ent.label_ == 'DATE':
                entities['dates'].append(ent.text)
        
        return entities
    
    def analyze_sentiment(self, text: str) -> Dict[str, float]:
        """Analyze sentiment polarity and subjectivity"""
        try:
            from textblob import TextBlob
            blob = TextBlob(text)
            return {
                'polarity': blob.sentiment.polarity,
                'subjectivity': blob.sentiment.subjectivity
            }
        except:
            return {'polarity': 0.0, 'subjectivity': 0.0}
    
    def detect_brand_impersonation(
        self,
        text: str,
        known_brands: List[str] = None
    ) -> Dict[str, any]:
        """
        Detect potential brand impersonation
        
        Args:
            text: Text to analyze
            known_brands: List of legitimate brand names
            
        Returns:
            Impersonation indicators
        """
        if known_brands is None:
            known_brands = [
                'PayPal', 'Amazon', 'Microsoft', 'Apple', 'Google',
                'Facebook', 'Netflix', 'Bank of America', 'Wells Fargo',
                'Chase', 'IRS', 'DHL', 'FedEx', 'UPS'
            ]
        
        entities = self.extract_entities(text)
        mentioned_brands = [
            brand for brand in known_brands
            if brand.lower() in text.lower()
        ]
        
        return {
            'mentioned_brands': mentioned_brands,
            'entities': entities,
            'brand_count': len(mentioned_brands)
        }


# Model factory for easy instantiation
def create_nlp_model(
    model_type: str = "bert",
    pretrained: bool = True,
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
) -> NLPPhishingDetector:
    """
    Factory function to create NLP models
    
    Args:
        model_type: Type of model (bert, roberta, distilbert)
        pretrained: Whether to use pretrained weights
        device: Device to load model on
        
    Returns:
        Initialized NLP model
    """
    model_mapping = {
        "bert": "bert-base-uncased",
        "roberta": "roberta-base",
        "distilbert": "distilbert-base-uncased",
        "bert-large": "bert-large-uncased"
    }
    
    model_name = model_mapping.get(model_type, "bert-base-uncased")
    
    model = NLPPhishingDetector(model_name=model_name)
    model.to(device)
    
    logger.info(f"NLP Model created: {model_name} on {device}")
    
    return model


if __name__ == "__main__":
    # Example usage
    print("Initializing NLP Phishing Detection Model...")
    
    model = create_nlp_model(model_type="bert")
    
    # Test email analysis
    test_email = {
        'subject': 'URGENT: Your account will be suspended',
        'body': '''Dear Customer,
        
        We have detected unusual activity on your account. 
        Please verify your identity immediately by clicking the link below.
        
        Failure to do so within 24 hours will result in permanent suspension.
        
        Click here: http://paypal-verify.suspicious.com
        
        Thank you,
        PayPal Security Team
        ''',
        'sender': 'security@paypal-verify.com'
    }
    
    result = model.analyze_email(
        subject=test_email['subject'],
        body=test_email['body'],
        sender=test_email['sender']
    )
    
    print("\n=== Analysis Results ===")
    print(f"Phishing Probability: {result['phishing_probability']:.2%}")
    print(f"Classification: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"\nExtracted Features:")
    for feature, value in result['features'].items():
        print(f"  {feature}: {value}")
