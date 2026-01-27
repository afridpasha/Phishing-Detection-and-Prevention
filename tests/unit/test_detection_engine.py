"""
Unit Tests - Detection Engine
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.detection_engine.url_analyzer import URLAnalyzer
from backend.detection_engine.ensemble import EnsembleDecisionEngine


class TestURLAnalyzer:
    def setup_method(self):
        self.analyzer = URLAnalyzer()
    
    def test_phishing_url_detection(self):
        url = "http://paypal-verify.suspicious.tk/login"
        result = self.analyzer.analyze_url(url, follow_redirects=False)
        assert result['suspicious_score'] > 0.5
        assert result['is_suspicious'] == True
    
    def test_legitimate_url(self):
        url = "https://www.google.com"
        result = self.analyzer.analyze_url(url, follow_redirects=False)
        assert result['suspicious_score'] < 0.5
    
    def test_ip_address_detection(self):
        url = "http://192.168.1.1/admin"
        result = self.analyzer.analyze_url(url, follow_redirects=False)
        assert 'ip_address_used' in result.get('pattern_indicators', [])
    
    def test_suspicious_tld(self):
        url = "http://malicious.tk"
        result = self.analyzer.analyze_url(url, follow_redirects=False)
        assert any('suspicious_tld' in str(i) for i in result.get('domain_indicators', []))


class TestEnsembleEngine:
    def setup_method(self):
        self.engine = EnsembleDecisionEngine()
    
    def test_high_risk_decision(self):
        result = self.engine.decide(
            nlp_result={'phishing_probability': 0.9, 'features': {}},
            url_result={'suspicious_score': 0.85},
            metadata={'type': 'test'}
        )
        assert result['action'] == 'block'
        assert result['risk_level'] == 'malicious'
    
    def test_low_risk_decision(self):
        result = self.engine.decide(
            nlp_result={'phishing_probability': 0.1, 'features': {}},
            url_result={'suspicious_score': 0.15},
            metadata={'type': 'test'}
        )
        assert result['action'] == 'allow'
        assert result['risk_level'] == 'safe'
    
    def test_confidence_calculation(self):
        result = self.engine.decide(
            nlp_result={'phishing_probability': 0.9, 'features': {}},
            cnn_result={'phishing_score': 0.88},
            url_result={'suspicious_score': 0.92},
            metadata={'type': 'test'}
        )
        assert result['confidence'] > 0.7


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
