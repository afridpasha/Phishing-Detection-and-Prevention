"""
CNN Visual Analysis Module - ResNet-50 Implementation
Real-Time Phishing Detection System

This module implements convolutional neural networks for webpage visual analysis,
detecting phishing through screenshot comparison and DOM structure analysis.
"""

import torch
import torch.nn as nn
import torchvision.models as models
import torchvision.transforms as transforms
from PIL import Image
import numpy as np
from typing import Dict, List, Tuple, Optional
import io
import base64
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CNNVisualAnalyzer(nn.Module):
    """
    CNN-based visual phishing detector
    
    Architecture:
    - Base: ResNet-50 or EfficientNet (pre-trained on ImageNet)
    - Custom layers: Global pooling → Dense(512) → Dense(256)
    - Output: Multi-class classification (legitimate/phishing/suspicious)
    - Additional: Siamese network for brand similarity comparison
    """
    
    def __init__(
        self,
        model_architecture: str = "resnet50",
        num_classes: int = 3,
        pretrained: bool = True,
        freeze_backbone: bool = False
    ):
        super(CNNVisualAnalyzer, self).__init__()
        
        self.model_architecture = model_architecture
        self.num_classes = num_classes
        
        # Load pre-trained backbone
        logger.info(f"Loading {model_architecture} architecture...")
        
        if model_architecture == "resnet50":
            backbone = models.resnet50(pretrained=pretrained)
            feature_dim = backbone.fc.in_features
            # Remove final FC layer
            self.backbone = nn.Sequential(*list(backbone.children())[:-1])
            
        elif model_architecture == "resnet34":
            backbone = models.resnet34(pretrained=pretrained)
            feature_dim = backbone.fc.in_features
            self.backbone = nn.Sequential(*list(backbone.children())[:-1])
            
        elif model_architecture == "efficientnet_b0":
            backbone = models.efficientnet_b0(pretrained=pretrained)
            feature_dim = backbone.classifier[1].in_features
            self.backbone = nn.Sequential(*list(backbone.children())[:-1])
            
        else:
            raise ValueError(f"Unsupported architecture: {model_architecture}")
        
        # Freeze backbone if specified
        if freeze_backbone:
            for param in self.backbone.parameters():
                param.requires_grad = False
        
        # Custom classification head
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(feature_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, num_classes)
        )
        
        # Softmax for probability distribution
        self.softmax = nn.Softmax(dim=1)
        
        # Image preprocessing transforms
        self.transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(
                mean=[0.485, 0.456, 0.406],
                std=[0.229, 0.224, 0.225]
            )
        ])
        
        logger.info(f"CNN Visual Analyzer initialized with {feature_dim}-dim features")
    
    def forward(
        self,
        images: torch.Tensor,
        return_features: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the model
        
        Args:
            images: Batch of preprocessed images
            return_features: Whether to return intermediate features
            
        Returns:
            Dictionary containing logits, probabilities, and predictions
        """
        # Extract features from backbone
        features = self.backbone(images)
        
        # Classification
        logits = self.classifier(features)
        probs = self.softmax(logits)
        predictions = torch.argmax(probs, dim=1)
        
        result = {
            'logits': logits,
            'probabilities': probs,
            'prediction': predictions
        }
        
        if return_features:
            result['features'] = features.squeeze()
        
        return result
    
    def preprocess_image(
        self,
        image: Image.Image
    ) -> torch.Tensor:
        """
        Preprocess image for model input
        
        Args:
            image: PIL Image object
            
        Returns:
            Preprocessed tensor
        """
        return self.transform(image).unsqueeze(0)
    
    def analyze_screenshot(
        self,
        screenshot: Image.Image,
        url: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Analyze webpage screenshot for phishing indicators
        
        Args:
            screenshot: PIL Image of webpage
            url: Optional URL being analyzed
            
        Returns:
            Analysis results with confidence scores
        """
        # Preprocess image
        image_tensor = self.preprocess_image(screenshot)
        
        # Set model to evaluation mode
        self.eval()
        
        with torch.no_grad():
            # Get predictions
            outputs = self.forward(
                images=image_tensor,
                return_features=True
            )
            
            probs = outputs['probabilities'][0]
            prediction = outputs['prediction'][0].item()
            
        # Map prediction to label
        labels = ['legitimate', 'phishing', 'suspicious']
        predicted_label = labels[prediction] if prediction < len(labels) else 'unknown'
        
        # Extract visual features
        visual_features = self._extract_visual_features(screenshot)
        
        return {
            'classification': predicted_label,
            'probabilities': {
                'legitimate': probs[0].item(),
                'phishing': probs[1].item() if len(probs) > 1 else 0.0,
                'suspicious': probs[2].item() if len(probs) > 2 else 0.0
            },
            'phishing_score': probs[1].item() if len(probs) > 1 else 0.0,
            'confidence': torch.max(probs).item(),
            'visual_features': visual_features,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'model': self.model_architecture
        }
    
    def _extract_visual_features(
        self,
        image: Image.Image
    ) -> Dict[str, any]:
        """
        Extract visual features from screenshot
        
        Returns:
            Dictionary of visual features
        """
        import cv2
        
        features = {}
        
        # Convert PIL to numpy array
        img_array = np.array(image)
        
        # Image dimensions
        features['width'], features['height'] = image.size
        features['aspect_ratio'] = features['width'] / features['height']
        
        # Color analysis
        if len(img_array.shape) == 3:
            # Average color channels
            features['avg_red'] = np.mean(img_array[:, :, 0])
            features['avg_green'] = np.mean(img_array[:, :, 1])
            features['avg_blue'] = np.mean(img_array[:, :, 2])
            
            # Color variance (complexity indicator)
            features['color_variance'] = np.var(img_array)
        
        # Edge detection (complexity/professionalism indicator)
        try:
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            edges = cv2.Canny(gray, 100, 200)
            features['edge_density'] = np.sum(edges > 0) / edges.size
        except:
            features['edge_density'] = 0.0
        
        # Brightness and contrast
        if len(img_array.shape) >= 2:
            features['brightness'] = np.mean(img_array)
            features['contrast'] = np.std(img_array)
        
        return features
    
    def compare_with_brand(
        self,
        screenshot: Image.Image,
        brand_reference: Image.Image
    ) -> Dict[str, float]:
        """
        Compare screenshot with known brand reference using Siamese approach
        
        Args:
            screenshot: Suspicious webpage screenshot
            brand_reference: Legitimate brand reference image
            
        Returns:
            Similarity metrics
        """
        # Preprocess both images
        img1 = self.preprocess_image(screenshot)
        img2 = self.preprocess_image(brand_reference)
        
        self.eval()
        
        with torch.no_grad():
            # Extract features
            features1 = self.backbone(img1).squeeze()
            features2 = self.backbone(img2).squeeze()
            
            # Calculate similarity metrics
            cosine_sim = nn.functional.cosine_similarity(
                features1.unsqueeze(0),
                features2.unsqueeze(0)
            ).item()
            
            # Euclidean distance
            euclidean_dist = torch.dist(features1, features2).item()
            
        return {
            'cosine_similarity': cosine_sim,
            'euclidean_distance': euclidean_dist,
            'is_similar': cosine_sim > 0.8,  # Threshold
            'similarity_score': (cosine_sim + 1) / 2  # Normalize to [0, 1]
        }


class DOMStructureAnalyzer:
    """
    Analyze HTML DOM structure for phishing indicators
    """
    
    def __init__(self):
        self.suspicious_patterns = []
    
    def analyze_dom(self, html_content: str, url: str) -> Dict[str, any]:
        """
        Analyze DOM structure of webpage
        
        Args:
            html_content: HTML source code
            url: Webpage URL
            
        Returns:
            DOM analysis results
        """
        from bs4 import BeautifulSoup
        import re
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        features = {}
        
        # Count elements
        features['total_elements'] = len(soup.find_all())
        features['form_count'] = len(soup.find_all('form'))
        features['input_count'] = len(soup.find_all('input'))
        features['iframe_count'] = len(soup.find_all('iframe'))
        features['script_count'] = len(soup.find_all('script'))
        
        # Check for password inputs
        password_inputs = soup.find_all('input', {'type': 'password'})
        features['has_password_field'] = len(password_inputs) > 0
        
        # Check for credit card inputs
        cc_patterns = [
            r'card.*number', r'credit.*card', r'cvv', r'cvc',
            r'expir', r'security.*code'
        ]
        features['has_cc_fields'] = any(
            re.search(pattern, str(soup), re.IGNORECASE)
            for pattern in cc_patterns
        )
        
        # Check for suspicious keywords in forms
        forms = soup.find_all('form')
        features['form_actions'] = [
            form.get('action', '') for form in forms
        ]
        
        # Detect external form submissions
        features['external_form_submission'] = any(
            action.startswith('http') and url not in action
            for action in features['form_actions']
            if action
        )
        
        # Check for hidden elements
        hidden_elements = soup.find_all(attrs={'style': re.compile(r'display:\s*none')})
        features['hidden_element_count'] = len(hidden_elements)
        
        # Meta tags analysis
        meta_tags = soup.find_all('meta')
        features['meta_count'] = len(meta_tags)
        
        # Title analysis
        title = soup.find('title')
        features['title'] = title.string if title else ''
        
        # Check for favicon
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        features['has_favicon'] = favicon is not None
        
        # Calculate DOM complexity score
        features['dom_complexity'] = self._calculate_complexity(features)
        
        return features
    
    def _calculate_complexity(self, features: Dict) -> float:
        """
        Calculate DOM complexity score (0-1)
        High complexity usually indicates legitimate sites
        """
        score = 0.0
        
        # More elements = more complex = more legitimate
        if features['total_elements'] > 100:
            score += 0.3
        
        # Presence of meta tags
        if features['meta_count'] > 5:
            score += 0.2
        
        # Has favicon
        if features['has_favicon']:
            score += 0.1
        
        # Multiple scripts (legitimate sites have analytics, etc.)
        if features['script_count'] > 3:
            score += 0.2
        
        # Not many hidden elements
        if features['hidden_element_count'] < 5:
            score += 0.2
        
        return min(score, 1.0)
    
    def detect_form_spoofing(
        self,
        html_content: str,
        claimed_brand: str
    ) -> Dict[str, any]:
        """
        Detect if forms are being used to spoof a legitimate brand
        
        Args:
            html_content: HTML source
            claimed_brand: Brand that page claims to be
            
        Returns:
            Spoofing indicators
        """
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        spoofing_indicators = []
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', '').lower()
            
            # Check if form submits to external domain
            if action.startswith('http') and claimed_brand.lower() not in action.lower():
                spoofing_indicators.append({
                    'type': 'external_submission',
                    'action': action,
                    'severity': 'high'
                })
            
            # Check for password collection on non-HTTPS
            if not action.startswith('https'):
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    spoofing_indicators.append({
                        'type': 'insecure_password_form',
                        'severity': 'critical'
                    })
        
        return {
            'is_spoofing': len(spoofing_indicators) > 0,
            'indicators': spoofing_indicators,
            'risk_level': 'high' if len(spoofing_indicators) > 0 else 'low'
        }


class BrandLogoDetector:
    """
    Detect and compare brand logos in screenshots
    Uses template matching and feature detection
    """
    
    def __init__(self):
        self.brand_templates = {}
    
    def load_brand_template(self, brand_name: str, template_path: str):
        """Load reference logo for a brand"""
        from PIL import Image
        template = Image.open(template_path)
        self.brand_templates[brand_name] = template
    
    def detect_logo(
        self,
        screenshot: Image.Image,
        brand_name: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Detect presence and authenticity of brand logos
        
        Args:
            screenshot: Webpage screenshot
            brand_name: Expected brand (if known)
            
        Returns:
            Logo detection results
        """
        import cv2
        
        # Convert PIL to OpenCV format
        img_cv = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
        
        results = {
            'logo_detected': False,
            'confidence': 0.0,
            'location': None,
            'matches_brand': None
        }
        
        if brand_name and brand_name in self.brand_templates:
            template = self.brand_templates[brand_name]
            template_cv = cv2.cvtColor(np.array(template), cv2.COLOR_RGB2BGR)
            
            # Template matching
            result = cv2.matchTemplate(img_cv, template_cv, cv2.TM_CCOEFF_NORMED)
            min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
            
            results['logo_detected'] = max_val > 0.7
            results['confidence'] = float(max_val)
            results['location'] = max_loc
            results['matches_brand'] = max_val > 0.8
        
        return results


# Model factory
def create_cnn_model(
    architecture: str = "resnet50",
    num_classes: int = 3,
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
) -> CNNVisualAnalyzer:
    """
    Factory function to create CNN models
    
    Args:
        architecture: Model architecture (resnet50, resnet34, efficientnet_b0)
        num_classes: Number of output classes
        device: Device to load model on
        
    Returns:
        Initialized CNN model
    """
    model = CNNVisualAnalyzer(
        model_architecture=architecture,
        num_classes=num_classes,
        pretrained=True
    )
    model.to(device)
    
    logger.info(f"CNN Model created: {architecture} on {device}")
    
    return model


if __name__ == "__main__":
    # Example usage
    print("Initializing CNN Visual Analysis Model...")
    
    model = create_cnn_model(architecture="resnet50")
    
    # Create dummy screenshot for testing
    dummy_screenshot = Image.new('RGB', (1024, 768), color='white')
    
    result = model.analyze_screenshot(
        screenshot=dummy_screenshot,
        url="https://example.com"
    )
    
    print("\n=== Visual Analysis Results ===")
    print(f"Classification: {result['classification'].upper()}")
    print(f"Phishing Score: {result['phishing_score']:.2%}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"\nProbabilities:")
    for label, prob in result['probabilities'].items():
        print(f"  {label}: {prob:.2%}")
    print(f"\nVisual Features:")
    for feature, value in result['visual_features'].items():
        print(f"  {feature}: {value}")
