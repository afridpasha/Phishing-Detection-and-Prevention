"""
Ensemble Decision Layer - Weighted Voting System
Real-Time Phishing Detection System

This module combines predictions from NLP, CNN, GNN, and URL analysis models
using weighted voting to produce final phishing detection decisions.
"""

import torch
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classifications"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Action(Enum):
    """Recommended actions"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class EnsembleDecisionEngine:
    """
    Ensemble decision engine combining multiple detection models
    
    Architecture:
    - Weighted voting from NLP, CNN, GNN, URL, and Threat Intel
    - Configurable weights and thresholds
    - Explainable decisions with feature importance
    - Confidence scoring and risk categorization
    
    Default Weights (from architecture):
    - NLP: 0.35
    - CNN: 0.25
    - GNN: 0.20
    - URL: 0.15
    - Threat Intel: 0.05
    """
    
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None
    ):
        # Default weights from architecture
        self.weights = weights or {
            'nlp': 0.35,
            'cnn': 0.25,
            'gnn': 0.20,
            'url': 0.15,
            'threat_intel': 0.05
        }
        
        # Validate weights sum to 1
        total_weight = sum(self.weights.values())
        if not np.isclose(total_weight, 1.0):
            logger.warning(f"Weights sum to {total_weight}, normalizing...")
            self.weights = {k: v/total_weight for k, v in self.weights.items()}
        
        # Decision thresholds
        self.thresholds = thresholds or {
            'safe': 0.5,        # Score < 0.5 = Safe
            'suspicious': 0.8,  # Score 0.5-0.8 = Suspicious
            'malicious': 0.8    # Score > 0.8 = Malicious
        }
        
        logger.info(f"Ensemble initialized with weights: {self.weights}")
    
    def decide(
        self,
        nlp_result: Optional[Dict] = None,
        cnn_result: Optional[Dict] = None,
        gnn_result: Optional[Dict] = None,
        url_result: Optional[Dict] = None,
        threat_intel_result: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> Dict[str, any]:
        """
        Make ensemble decision combining all model outputs
        
        Args:
            nlp_result: NLP model analysis result
            cnn_result: CNN visual analysis result
            gnn_result: GNN domain analysis result
            url_result: URL analyzer result
            threat_intel_result: Threat intelligence lookup result
            metadata: Additional context (user, timestamp, etc.)
            
        Returns:
            Comprehensive decision with explanations
        """
        # Collect individual scores
        scores = {}
        explanations = {}
        
        # NLP Score
        if nlp_result:
            scores['nlp'] = self._extract_nlp_score(nlp_result)
            explanations['nlp'] = self._explain_nlp(nlp_result)
        
        # CNN Score
        if cnn_result:
            scores['cnn'] = self._extract_cnn_score(cnn_result)
            explanations['cnn'] = self._explain_cnn(cnn_result)
        
        # GNN Score
        if gnn_result:
            scores['gnn'] = self._extract_gnn_score(gnn_result)
            explanations['gnn'] = self._explain_gnn(gnn_result)
        
        # URL Score
        if url_result:
            scores['url'] = self._extract_url_score(url_result)
            explanations['url'] = self._explain_url(url_result)
        
        # Threat Intel Score
        if threat_intel_result:
            scores['threat_intel'] = self._extract_threat_intel_score(threat_intel_result)
            explanations['threat_intel'] = self._explain_threat_intel(threat_intel_result)
        
        # Calculate weighted ensemble score
        final_score = self._calculate_weighted_score(scores)
        
        # Determine risk level and action
        risk_level = self._categorize_risk(final_score)
        action = self._determine_action(risk_level, final_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(scores, final_score)
        
        # Generate explanation
        explanation = self._generate_explanation(
            scores,
            explanations,
            final_score,
            risk_level
        )
        
        # Build result
        result = {
            'timestamp': datetime.now().isoformat(),
            'final_score': final_score,
            'risk_level': risk_level.value,
            'action': action.value,
            'confidence': confidence,
            'individual_scores': scores,
            'explanation': explanation,
            'metadata': metadata or {}
        }
        
        # Add model contributions
        result['model_contributions'] = self._calculate_contributions(scores)
        
        logger.info(f"Decision: {action.value} | Score: {final_score:.2f} | Risk: {risk_level.value}")
        
        return result
    
    def _extract_nlp_score(self, result: Dict) -> float:
        """Extract phishing score from NLP result"""
        return result.get('phishing_probability', 0.5)
    
    def _extract_cnn_score(self, result: Dict) -> float:
        """Extract phishing score from CNN result"""
        return result.get('phishing_score', 0.5)
    
    def _extract_gnn_score(self, result: Dict) -> float:
        """Extract risk score from GNN result"""
        return result.get('risk_score', 0.5)
    
    def _extract_url_score(self, result: Dict) -> float:
        """Extract suspicious score from URL result"""
        return result.get('suspicious_score', 0.5)
    
    def _extract_threat_intel_score(self, result: Dict) -> float:
        """Extract threat score from intel result"""
        # Binary: in blocklist (1.0) or not (0.0)
        return 1.0 if result.get('in_blocklist', False) else 0.0
    
    def _calculate_weighted_score(self, scores: Dict[str, float]) -> float:
        """
        Calculate weighted ensemble score
        
        Formula: Final_Score = Σ(Model_Score × Weight)
        """
        weighted_sum = 0.0
        total_weight = 0.0
        
        for model, score in scores.items():
            if model in self.weights:
                weight = self.weights[model]
                weighted_sum += score * weight
                total_weight += weight
        
        # Normalize by actual total weight used
        if total_weight > 0:
            final_score = weighted_sum / total_weight
        else:
            final_score = 0.5  # Default neutral score
        
        return np.clip(final_score, 0.0, 1.0)
    
    def _categorize_risk(self, score: float) -> RiskLevel:
        """Categorize final score into risk levels"""
        if score < self.thresholds['safe']:
            return RiskLevel.SAFE
        elif score < self.thresholds['malicious']:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.MALICIOUS
    
    def _determine_action(self, risk_level: RiskLevel, score: float) -> Action:
        """Determine recommended action based on risk"""
        if risk_level == RiskLevel.SAFE:
            return Action.ALLOW
        elif risk_level == RiskLevel.SUSPICIOUS:
            return Action.WARN
        else:
            return Action.BLOCK
    
    def _calculate_confidence(
        self,
        scores: Dict[str, float],
        final_score: float
    ) -> float:
        """
        Calculate confidence in the decision
        Based on agreement between models
        """
        if not scores:
            return 0.0
        
        score_values = list(scores.values())
        
        # Calculate variance (low variance = high agreement = high confidence)
        variance = np.var(score_values)
        
        # Calculate consensus (how many models agree with final decision)
        threshold = self.thresholds['malicious']
        final_classification = 1 if final_score > threshold else 0
        
        agreements = sum(
            1 for score in score_values
            if (score > threshold) == final_classification
        )
        consensus = agreements / len(score_values)
        
        # Confidence is combination of low variance and high consensus
        confidence = (1 - min(variance, 1.0)) * 0.5 + consensus * 0.5
        
        return np.clip(confidence, 0.0, 1.0)
    
    def _calculate_contributions(self, scores: Dict[str, float]) -> Dict[str, float]:
        """Calculate each model's contribution to final decision"""
        contributions = {}
        
        for model, score in scores.items():
            if model in self.weights:
                contribution = score * self.weights[model]
                contributions[model] = contribution
        
        return contributions
    
    def _explain_nlp(self, result: Dict) -> str:
        """Generate explanation from NLP analysis"""
        prob = result.get('phishing_probability', 0)
        features = result.get('features', {})
        
        explanations = []
        
        if prob > 0.7:
            explanations.append("High phishing indicators in text content")
        
        if features.get('urgency_score', 0) > 0.3:
            explanations.append("Urgent language detected")
        
        if features.get('threat_score', 0) > 0.3:
            explanations.append("Threatening language found")
        
        if features.get('generic_greeting'):
            explanations.append("Generic greeting (not personalized)")
        
        return " | ".join(explanations) if explanations else "Text analysis completed"
    
    def _explain_cnn(self, result: Dict) -> str:
        """Generate explanation from CNN analysis"""
        classification = result.get('classification', 'unknown')
        score = result.get('phishing_score', 0)
        
        if classification == 'phishing' or score > 0.7:
            return "Visual analysis indicates brand impersonation"
        elif classification == 'suspicious':
            return "Visual elements show suspicious characteristics"
        else:
            return "Visual analysis shows legitimate design"
    
    def _explain_gnn(self, result: Dict) -> str:
        """Generate explanation from GNN analysis"""
        risk_score = result.get('risk_score', 0)
        network_size = result.get('network_size', 0)
        
        if risk_score > 0.7:
            return f"Domain network exhibits malicious patterns ({network_size} related domains)"
        elif risk_score > 0.5:
            return "Domain has suspicious infrastructure relationships"
        else:
            return "Domain infrastructure appears legitimate"
    
    def _explain_url(self, result: Dict) -> str:
        """Generate explanation from URL analysis"""
        indicators = []
        
        if result.get('pattern_indicators'):
            indicators.extend(result['pattern_indicators'][:2])
        
        if result.get('encoding_indicators'):
            indicators.extend(result['encoding_indicators'][:2])
        
        if result.get('domain_indicators'):
            indicators.extend(result['domain_indicators'][:2])
        
        if indicators:
            return f"URL issues: {', '.join(indicators[:3])}"
        else:
            return "URL structure appears normal"
    
    def _explain_threat_intel(self, result: Dict) -> str:
        """Generate explanation from threat intelligence"""
        if result.get('in_blocklist'):
            return "Domain found in threat intelligence blocklists"
        elif result.get('threat_score', 0) > 0.5:
            return "Domain has negative reputation history"
        else:
            return "No threat intelligence matches found"
    
    def _generate_explanation(
        self,
        scores: Dict[str, float],
        explanations: Dict[str, str],
        final_score: float,
        risk_level: RiskLevel
    ) -> Dict[str, any]:
        """Generate comprehensive explanation"""
        explanation = {
            'summary': self._generate_summary(final_score, risk_level),
            'details': explanations,
            'top_indicators': self._get_top_indicators(scores, explanations),
            'recommendation': self._get_recommendation(risk_level)
        }
        
        return explanation
    
    def _generate_summary(self, score: float, risk_level: RiskLevel) -> str:
        """Generate summary explanation"""
        if risk_level == RiskLevel.MALICIOUS:
            return f"High confidence phishing attempt detected (Score: {score:.2%})"
        elif risk_level == RiskLevel.SUSPICIOUS:
            return f"Suspicious indicators found, proceed with caution (Score: {score:.2%})"
        else:
            return f"Content appears legitimate (Score: {score:.2%})"
    
    def _get_top_indicators(
        self,
        scores: Dict[str, float],
        explanations: Dict[str, str]
    ) -> List[str]:
        """Get top contributing indicators"""
        # Sort models by score
        sorted_models = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        top_indicators = []
        for model, score in sorted_models[:3]:
            if score > 0.5 and model in explanations:
                top_indicators.append(f"{model.upper()}: {explanations[model]}")
        
        return top_indicators
    
    def _get_recommendation(self, risk_level: RiskLevel) -> str:
        """Get user-facing recommendation"""
        recommendations = {
            RiskLevel.SAFE: "This content appears safe to interact with.",
            RiskLevel.SUSPICIOUS: "Exercise caution. Verify sender/source before proceeding.",
            RiskLevel.MALICIOUS: "Do not interact with this content. It appears to be a phishing attempt."
        }
        
        return recommendations.get(risk_level, "Unknown risk level")
    
    def update_weights(self, new_weights: Dict[str, float]):
        """Update model weights dynamically"""
        # Validate and normalize
        total = sum(new_weights.values())
        if total > 0:
            self.weights = {k: v/total for k, v in new_weights.items()}
            logger.info(f"Weights updated: {self.weights}")
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update decision thresholds"""
        self.thresholds.update(new_thresholds)
        logger.info(f"Thresholds updated: {self.thresholds}")
    
    def batch_decide(
        self,
        predictions: List[Dict[str, Dict]]
    ) -> List[Dict[str, any]]:
        """
        Process multiple predictions in batch
        
        Args:
            predictions: List of dictionaries with model results
            
        Returns:
            List of ensemble decisions
        """
        results = []
        
        for pred in predictions:
            decision = self.decide(
                nlp_result=pred.get('nlp'),
                cnn_result=pred.get('cnn'),
                gnn_result=pred.get('gnn'),
                url_result=pred.get('url'),
                threat_intel_result=pred.get('threat_intel'),
                metadata=pred.get('metadata')
            )
            results.append(decision)
        
        return results


class DecisionLogger:
    """Log decisions for analysis and retraining"""
    
    def __init__(self, log_file: str = "decisions.log"):
        self.log_file = log_file
        self.decisions = []
    
    def log_decision(self, decision: Dict, user_feedback: Optional[str] = None):
        """Log a decision with optional user feedback"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'decision': decision,
            'user_feedback': user_feedback
        }
        
        self.decisions.append(log_entry)
        
        # Write to file
        import json
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def get_statistics(self) -> Dict[str, any]:
        """Get decision statistics"""
        if not self.decisions:
            return {}
        
        total = len(self.decisions)
        actions = {}
        risk_levels = {}
        
        for entry in self.decisions:
            action = entry['decision'].get('action', 'unknown')
            risk = entry['decision'].get('risk_level', 'unknown')
            
            actions[action] = actions.get(action, 0) + 1
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        return {
            'total_decisions': total,
            'actions': actions,
            'risk_levels': risk_levels,
            'avg_score': np.mean([
                d['decision'].get('final_score', 0) for d in self.decisions
            ]),
            'avg_confidence': np.mean([
                d['decision'].get('confidence', 0) for d in self.decisions
            ])
        }


if __name__ == "__main__":
    # Example usage
    print("Initializing Ensemble Decision Engine...")
    
    engine = EnsembleDecisionEngine()
    
    # Simulate model results for a phishing email
    test_case = {
        'nlp': {
            'phishing_probability': 0.85,
            'is_phishing': True,
            'confidence': 0.90,
            'features': {
                'urgency_score': 0.7,
                'threat_score': 0.6,
                'generic_greeting': True
            }
        },
        'cnn': {
            'classification': 'phishing',
            'phishing_score': 0.78,
            'confidence': 0.82
        },
        'gnn': {
            'risk_score': 0.72,
            'is_malicious': True,
            'network_size': 5
        },
        'url': {
            'suspicious_score': 0.81,
            'is_suspicious': True,
            'pattern_indicators': ['brand_impersonation: paypal'],
            'domain_indicators': ['suspicious_tld: .tk']
        },
        'threat_intel': {
            'in_blocklist': False,
            'threat_score': 0.3
        }
    }
    
    # Make decision
    decision = engine.decide(
        nlp_result=test_case['nlp'],
        cnn_result=test_case['cnn'],
        gnn_result=test_case['gnn'],
        url_result=test_case['url'],
        threat_intel_result=test_case['threat_intel'],
        metadata={'source': 'email', 'user_id': 'test_user'}
    )
    
    print("\n" + "="*70)
    print("ENSEMBLE DECISION RESULTS")
    print("="*70)
    print(f"\nFinal Score: {decision['final_score']:.2%}")
    print(f"Risk Level: {decision['risk_level'].upper()}")
    print(f"Action: {decision['action'].upper()}")
    print(f"Confidence: {decision['confidence']:.2%}")
    
    print(f"\nSummary: {decision['explanation']['summary']}")
    print(f"\nRecommendation: {decision['explanation']['recommendation']}")
    
    print(f"\nTop Indicators:")
    for indicator in decision['explanation']['top_indicators']:
        print(f"  • {indicator}")
    
    print(f"\nModel Contributions:")
    for model, contribution in decision['model_contributions'].items():
        print(f"  {model.upper()}: {contribution:.3f}")
