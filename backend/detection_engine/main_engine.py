"""
Main Detection Engine - Orchestrator
Real-Time Phishing Detection System

This module orchestrates all detection models (NLP, CNN, GNN, URL)
and combines their predictions using the ensemble decision engine.
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
import time

from .nlp_model import create_nlp_model, NLPPhishingDetector
from .cnn_model import create_cnn_model, CNNVisualAnalyzer, DOMStructureAnalyzer
from .gnn_model import create_gnn_model, GNNDomainAnalyzer, DomainFeatureExtractor
from .url_analyzer import URLAnalyzer, extract_urls_from_text
from .ensemble import EnsembleDecisionEngine, DecisionLogger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDetectionEngine:
    """
    Main orchestrator for phishing detection
    
    Coordinates all detection models and provides unified interface
    for analysis requests.
    """
    
    def __init__(
        self,
        load_models: bool = True,
        enable_parallel: bool = True,
        max_workers: int = 4
    ):
        """
        Initialize detection engine
        
        Args:
            load_models: Whether to load ML models on initialization
            enable_parallel: Enable parallel model execution
            max_workers: Max threads for parallel execution
        """
        self.enable_parallel = enable_parallel
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Initialize models
        logger.info("Initializing Phishing Detection Engine...")
        
        self.nlp_model = None
        self.cnn_model = None
        self.gnn_model = None
        self.url_analyzer = URLAnalyzer()
        self.ensemble_engine = EnsembleDecisionEngine()
        self.decision_logger = DecisionLogger()
        
        # Auxiliary components
        self.dom_analyzer = DOMStructureAnalyzer()
        self.domain_extractor = DomainFeatureExtractor()
        
        if load_models:
            self._load_models()
        
        # Performance metrics
        self.metrics = {
            'total_requests': 0,
            'total_latency': 0.0,
            'model_latencies': {
                'nlp': 0.0,
                'cnn': 0.0,
                'gnn': 0.0,
                'url': 0.0
            }
        }
        
        logger.info("Detection Engine initialized successfully")
    
    def _load_models(self):
        """Load all ML models"""
        try:
            logger.info("Loading NLP model...")
            self.nlp_model = create_nlp_model(model_type="bert")
            
            logger.info("Loading CNN model...")
            self.cnn_model = create_cnn_model(architecture="resnet50")
            
            logger.info("Loading GNN model...")
            self.gnn_model = create_gnn_model()
            
            logger.info("All models loaded successfully")
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    async def analyze_email(
        self,
        subject: str,
        body: str,
        sender: Optional[str] = None,
        html_content: Optional[str] = None,
        attachments: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze email for phishing indicators
        
        Args:
            subject: Email subject line
            body: Email body content
            sender: Sender email address
            html_content: HTML source of email
            attachments: List of attachment filenames
            
        Returns:
            Comprehensive analysis result
        """
        start_time = time.time()
        
        logger.info(f"Analyzing email: {subject[:50]}...")
        
        # Extract URLs from email
        urls = extract_urls_from_text(body)
        
        # Prepare analysis tasks
        tasks = []
        
        # NLP Analysis
        if self.nlp_model:
            nlp_task = self._run_nlp_analysis(subject, body, sender, urls)
            tasks.append(('nlp', nlp_task))
        
        # URL Analysis
        if urls:
            url_task = self._run_url_analysis(urls[0])  # Analyze first URL
            tasks.append(('url', url_task))
        
        # Domain Analysis (from sender/URLs)
        if sender or urls:
            domain = self._extract_domain(sender or urls[0])
            if domain:
                gnn_task = self._run_gnn_analysis(domain)
                tasks.append(('gnn', gnn_task))
        
        # DOM Analysis if HTML provided
        dom_result = None
        if html_content and urls:
            dom_result = self.dom_analyzer.analyze_dom(html_content, urls[0])
        
        # Execute analysis tasks
        if self.enable_parallel:
            results = await self._execute_parallel(tasks)
        else:
            results = await self._execute_sequential(tasks)
        
        # Combine results and make decision
        decision = self.ensemble_engine.decide(
            nlp_result=results.get('nlp'),
            cnn_result=None,  # No screenshot for email
            gnn_result=results.get('gnn'),
            url_result=results.get('url'),
            threat_intel_result=None,  # TODO: Integrate threat intel
            metadata={
                'type': 'email',
                'subject': subject[:100],
                'sender': sender,
                'url_count': len(urls),
                'has_attachments': bool(attachments)
            }
        )
        
        # Add DOM analysis if available
        if dom_result:
            decision['dom_analysis'] = dom_result
        
        # Update metrics
        latency = time.time() - start_time
        self._update_metrics(latency)
        decision['latency_ms'] = latency * 1000
        
        # Log decision
        self.decision_logger.log_decision(decision)
        
        logger.info(f"Analysis complete: {decision['action']} (latency: {latency*1000:.1f}ms)")
        
        return decision
    
    async def analyze_url(
        self,
        url: str,
        screenshot: Optional[Any] = None,
        html_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze URL for phishing indicators
        
        Args:
            url: URL to analyze
            screenshot: PIL Image of webpage (optional)
            html_content: HTML source code (optional)
            
        Returns:
            Comprehensive analysis result
        """
        start_time = time.time()
        
        logger.info(f"Analyzing URL: {url}")
        
        tasks = []
        
        # URL Analysis
        url_task = self._run_url_analysis(url)
        tasks.append(('url', url_task))
        
        # CNN Analysis (if screenshot provided)
        if screenshot and self.cnn_model:
            cnn_task = self._run_cnn_analysis(screenshot, url)
            tasks.append(('cnn', cnn_task))
        
        # Domain Analysis
        domain = self._extract_domain(url)
        if domain and self.gnn_model:
            gnn_task = self._run_gnn_analysis(domain)
            tasks.append(('gnn', gnn_task))
        
        # DOM Analysis
        dom_result = None
        if html_content:
            dom_result = self.dom_analyzer.analyze_dom(html_content, url)
        
        # Execute analysis tasks
        if self.enable_parallel:
            results = await self._execute_parallel(tasks)
        else:
            results = await self._execute_sequential(tasks)
        
        # Make decision
        decision = self.ensemble_engine.decide(
            nlp_result=None,  # No text for URL-only analysis
            cnn_result=results.get('cnn'),
            gnn_result=results.get('gnn'),
            url_result=results.get('url'),
            threat_intel_result=None,
            metadata={
                'type': 'url',
                'url': url,
                'has_screenshot': screenshot is not None,
                'has_html': html_content is not None
            }
        )
        
        if dom_result:
            decision['dom_analysis'] = dom_result
        
        # Update metrics
        latency = time.time() - start_time
        self._update_metrics(latency)
        decision['latency_ms'] = latency * 1000
        
        self.decision_logger.log_decision(decision)
        
        logger.info(f"URL analysis complete: {decision['action']} (latency: {latency*1000:.1f}ms)")
        
        return decision
    
    async def analyze_sms(
        self,
        message: str,
        sender: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze SMS/text message for phishing (smishing)
        
        Args:
            message: SMS message content
            sender: Sender phone number/ID
            
        Returns:
            Analysis result
        """
        start_time = time.time()
        
        logger.info("Analyzing SMS message...")
        
        # Extract URLs
        urls = extract_urls_from_text(message)
        
        tasks = []
        
        # NLP Analysis
        if self.nlp_model:
            nlp_task = self._run_nlp_analysis("SMS", message, sender, urls)
            tasks.append(('nlp', nlp_task))
        
        # URL Analysis if URLs present
        if urls:
            url_task = self._run_url_analysis(urls[0])
            tasks.append(('url', url_task))
        
        # Execute tasks
        if self.enable_parallel:
            results = await self._execute_parallel(tasks)
        else:
            results = await self._execute_sequential(tasks)
        
        # Make decision
        decision = self.ensemble_engine.decide(
            nlp_result=results.get('nlp'),
            url_result=results.get('url'),
            metadata={
                'type': 'sms',
                'sender': sender,
                'message_length': len(message),
                'url_count': len(urls)
            }
        )
        
        latency = time.time() - start_time
        self._update_metrics(latency)
        decision['latency_ms'] = latency * 1000
        
        self.decision_logger.log_decision(decision)
        
        return decision
    
    async def _run_nlp_analysis(
        self,
        subject: str,
        body: str,
        sender: Optional[str],
        urls: List[str]
    ) -> Dict:
        """Run NLP model analysis"""
        if not self.nlp_model:
            return None
        
        try:
            result = self.nlp_model.analyze_email(
                subject=subject,
                body=body,
                sender=sender,
                urls=urls
            )
            return result
        except Exception as e:
            logger.error(f"NLP analysis error: {e}")
            return None
    
    async def _run_cnn_analysis(self, screenshot, url: str) -> Dict:
        """Run CNN model analysis"""
        if not self.cnn_model:
            return None
        
        try:
            result = self.cnn_model.analyze_screenshot(
                screenshot=screenshot,
                url=url
            )
            return result
        except Exception as e:
            logger.error(f"CNN analysis error: {e}")
            return None
    
    async def _run_gnn_analysis(self, domain: str) -> Dict:
        """Run GNN model analysis"""
        if not self.gnn_model:
            return None
        
        try:
            # Extract domain features
            features = {
                domain: self.domain_extractor.extract_domain_features(domain)
            }
            
            result = self.gnn_model.analyze_domain_network(
                domain=domain,
                related_domains=[],
                domain_features=features
            )
            return result
        except Exception as e:
            logger.error(f"GNN analysis error: {e}")
            return None
    
    async def _run_url_analysis(self, url: str) -> Dict:
        """Run URL analyzer"""
        try:
            result = self.url_analyzer.analyze_url(
                url=url,
                follow_redirects=False  # Fast mode
            )
            return result
        except Exception as e:
            logger.error(f"URL analysis error: {e}")
            return None
    
    async def _execute_parallel(self, tasks: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """Execute analysis tasks in parallel"""
        results = {}
        
        # Run all tasks concurrently
        task_results = await asyncio.gather(
            *[task for _, task in tasks],
            return_exceptions=True
        )
        
        # Map results back to model names
        for (name, _), result in zip(tasks, task_results):
            if not isinstance(result, Exception):
                results[name] = result
            else:
                logger.error(f"Task {name} failed: {result}")
                results[name] = None
        
        return results
    
    async def _execute_sequential(self, tasks: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """Execute analysis tasks sequentially"""
        results = {}
        
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
            except Exception as e:
                logger.error(f"Task {name} failed: {e}")
                results[name] = None
        
        return results
    
    def _extract_domain(self, text: str) -> Optional[str]:
        """Extract domain from email address or URL"""
        import re
        from urllib.parse import urlparse
        
        if not text:
            return None
        
        # Check if it's a URL
        if text.startswith('http'):
            parsed = urlparse(text)
            return parsed.netloc
        
        # Check if it's an email address
        email_match = re.search(r'@([a-zA-Z0-9.-]+)', text)
        if email_match:
            return email_match.group(1)
        
        return None
    
    def _update_metrics(self, latency: float):
        """Update performance metrics"""
        self.metrics['total_requests'] += 1
        self.metrics['total_latency'] += latency
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        stats = {
            'total_requests': self.metrics['total_requests'],
            'average_latency_ms': (
                self.metrics['total_latency'] / self.metrics['total_requests'] * 1000
                if self.metrics['total_requests'] > 0 else 0
            ),
            'decision_statistics': self.decision_logger.get_statistics()
        }
        
        return stats
    
    def reload_models(self):
        """Reload all models (for updates)"""
        logger.info("Reloading models...")
        self._load_models()
        logger.info("Models reloaded successfully")
    
    def update_ensemble_weights(self, weights: Dict[str, float]):
        """Update ensemble model weights"""
        self.ensemble_engine.update_weights(weights)
    
    def shutdown(self):
        """Cleanup resources"""
        logger.info("Shutting down detection engine...")
        self.executor.shutdown(wait=True)
        logger.info("Detection engine shutdown complete")


# Global engine instance
_engine_instance = None


def get_engine() -> PhishingDetectionEngine:
    """Get singleton engine instance"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PhishingDetectionEngine()
    return _engine_instance


if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        print("Initializing Detection Engine...")
        engine = PhishingDetectionEngine(load_models=False)  # Fast mode for testing
        
        # Test email analysis
        print("\n" + "="*70)
        print("TEST 1: Email Analysis")
        print("="*70)
        
        result = await engine.analyze_email(
            subject="URGENT: Your account will be suspended",
            body="""Dear Customer,
            
            We detected unusual activity on your PayPal account.
            Please verify your identity immediately by clicking here:
            http://paypal-verify.suspicious.tk/login
            
            Failure to act within 24 hours will result in account suspension.
            
            PayPal Security Team
            """,
            sender="security@paypal-verify.com"
        )
        
        print(f"\nDecision: {result['action'].upper()}")
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Final Score: {result['final_score']:.2%}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Latency: {result['latency_ms']:.1f}ms")
        print(f"\nSummary: {result['explanation']['summary']}")
        
        # Test URL analysis
        print("\n" + "="*70)
        print("TEST 2: URL Analysis")
        print("="*70)
        
        result = await engine.analyze_url(
            url="http://192.168.1.1/admin?redirect=https://malicious.com"
        )
        
        print(f"\nDecision: {result['action'].upper()}")
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Final Score: {result['final_score']:.2%}")
        print(f"Latency: {result['latency_ms']:.1f}ms")
        
        # Statistics
        print("\n" + "="*70)
        print("ENGINE STATISTICS")
        print("="*70)
        stats = engine.get_statistics()
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Average Latency: {stats['average_latency_ms']:.1f}ms")
        
        engine.shutdown()
    
    asyncio.run(main())
