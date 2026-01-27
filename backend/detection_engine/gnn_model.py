"""
GNN Graph Analysis Module - Domain Relationship Mapping
Real-Time Phishing Detection System

This module implements Graph Neural Networks for analyzing domain relationships,
detecting malicious infrastructure through network topology analysis.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool
from torch_geometric.data import Data, Batch
import networkx as nx
import numpy as np
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GNNDomainAnalyzer(nn.Module):
    """
    Graph Neural Network for domain relationship analysis
    
    Architecture:
    - 3-layer Graph Convolutional Network (GCN)
    - Node embeddings: 128-dimensional vectors
    - Aggregation: Mean pooling across neighborhoods
    - Output: Domain risk score (0-1 scale)
    """
    
    def __init__(
        self,
        input_dim: int = 128,
        hidden_dim: int = 256,
        output_dim: int = 1,
        num_layers: int = 3,
        dropout: float = 0.3
    ):
        super(GNNDomainAnalyzer, self).__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Graph convolutional layers
        self.convs = nn.ModuleList()
        self.batch_norms = nn.ModuleList()
        
        # First layer
        self.convs.append(GCNConv(input_dim, hidden_dim))
        self.batch_norms.append(nn.BatchNorm1d(hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
            self.batch_norms.append(nn.BatchNorm1d(hidden_dim))
        
        # Output layer
        self.convs.append(GCNConv(hidden_dim, hidden_dim))
        self.batch_norms.append(nn.BatchNorm1d(hidden_dim))
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, output_dim),
            nn.Sigmoid()
        )
        
        self.dropout = dropout
        
        logger.info(f"GNN Model initialized with {num_layers} layers")
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through GNN
        
        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Graph connectivity [2, num_edges]
            batch: Batch assignment for nodes
            
        Returns:
            Dictionary with predictions and embeddings
        """
        # Apply graph convolutions
        for i, (conv, bn) in enumerate(zip(self.convs, self.batch_norms)):
            x = conv(x, edge_index)
            x = bn(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Graph-level pooling
        if batch is not None:
            x_pooled = global_mean_pool(x, batch)
        else:
            x_pooled = torch.mean(x, dim=0, keepdim=True)
        
        # Classification
        risk_score = self.classifier(x_pooled)
        
        return {
            'risk_score': risk_score,
            'node_embeddings': x,
            'graph_embedding': x_pooled
        }
    
    def analyze_domain_network(
        self,
        domain: str,
        related_domains: List[str],
        domain_features: Dict[str, Dict]
    ) -> Dict[str, any]:
        """
        Analyze a domain within its network context
        
        Args:
            domain: Primary domain to analyze
            related_domains: Related domains (subdomains, redirects, etc.)
            domain_features: Feature dictionary for each domain
            
        Returns:
            Risk analysis results
        """
        # Build graph
        graph_data = self._build_domain_graph(
            domain,
            related_domains,
            domain_features
        )
        
        # Set model to evaluation mode
        self.eval()
        
        with torch.no_grad():
            # Get predictions
            outputs = self.forward(
                x=graph_data.x,
                edge_index=graph_data.edge_index
            )
            
            risk_score = outputs['risk_score'].item()
        
        # Analyze graph structure
        structure_analysis = self._analyze_graph_structure(
            domain,
            related_domains,
            domain_features
        )
        
        return {
            'domain': domain,
            'risk_score': risk_score,
            'is_malicious': risk_score > 0.7,
            'risk_level': self._categorize_risk(risk_score),
            'network_size': len(related_domains) + 1,
            'structure_analysis': structure_analysis,
            'timestamp': datetime.now().isoformat()
        }
    
    def _build_domain_graph(
        self,
        primary_domain: str,
        related_domains: List[str],
        domain_features: Dict[str, Dict]
    ) -> Data:
        """
        Build PyTorch Geometric graph from domain relationships
        
        Returns:
            PyTorch Geometric Data object
        """
        # Create node list
        all_domains = [primary_domain] + related_domains
        node_features = []
        
        # Extract features for each domain
        for domain in all_domains:
            if domain in domain_features:
                features = self._domain_to_feature_vector(domain_features[domain])
            else:
                features = torch.zeros(self.input_dim)
            node_features.append(features)
        
        x = torch.stack(node_features)
        
        # Create edges (connected if related)
        edge_list = []
        for i in range(len(all_domains)):
            for j in range(i + 1, len(all_domains)):
                # Add bidirectional edges
                edge_list.append([i, j])
                edge_list.append([j, i])
        
        if edge_list:
            edge_index = torch.tensor(edge_list, dtype=torch.long).t()
        else:
            # Self-loops if no edges
            edge_index = torch.tensor([[0], [0]], dtype=torch.long)
        
        return Data(x=x, edge_index=edge_index)
    
    def _domain_to_feature_vector(
        self,
        domain_info: Dict
    ) -> torch.Tensor:
        """
        Convert domain information to feature vector
        
        Args:
            domain_info: Dictionary with domain attributes
            
        Returns:
            Feature tensor
        """
        features = []
        
        # Domain age (normalized)
        age_days = domain_info.get('age_days', 0)
        features.append(min(age_days / 365, 10.0))  # Cap at 10 years
        
        # DNS record count
        dns_count = domain_info.get('dns_records', 0)
        features.append(min(dns_count / 10, 1.0))
        
        # SSL certificate validity
        ssl_valid = domain_info.get('ssl_valid', False)
        features.append(1.0 if ssl_valid else 0.0)
        
        # Reputation score
        reputation = domain_info.get('reputation_score', 0.5)
        features.append(reputation)
        
        # Traffic rank (Alexa/similar)
        traffic_rank = domain_info.get('traffic_rank', 1000000)
        features.append(1.0 / (1.0 + np.log(traffic_rank)))
        
        # WHOIS privacy
        whois_private = domain_info.get('whois_private', False)
        features.append(1.0 if whois_private else 0.0)
        
        # Geographic risk
        country_risk = domain_info.get('country_risk_score', 0.5)
        features.append(country_risk)
        
        # Pad or truncate to input_dim
        feature_tensor = torch.tensor(features, dtype=torch.float32)
        if len(features) < self.input_dim:
            padding = torch.zeros(self.input_dim - len(features))
            feature_tensor = torch.cat([feature_tensor, padding])
        else:
            feature_tensor = feature_tensor[:self.input_dim]
        
        return feature_tensor
    
    def _analyze_graph_structure(
        self,
        primary_domain: str,
        related_domains: List[str],
        domain_features: Dict
    ) -> Dict[str, any]:
        """
        Analyze graph structure using NetworkX
        
        Returns:
            Structural metrics
        """
        # Build NetworkX graph
        G = nx.Graph()
        
        all_domains = [primary_domain] + related_domains
        G.add_nodes_from(all_domains)
        
        # Add edges
        for i in range(len(all_domains)):
            for j in range(i + 1, len(all_domains)):
                G.add_edge(all_domains[i], all_domains[j])
        
        # Calculate metrics
        metrics = {}
        
        try:
            # Degree centrality
            degree_cent = nx.degree_centrality(G)
            metrics['primary_centrality'] = degree_cent.get(primary_domain, 0)
            
            # Clustering coefficient
            clustering = nx.clustering(G)
            metrics['clustering_coefficient'] = clustering.get(primary_domain, 0)
            
            # Graph density
            metrics['graph_density'] = nx.density(G)
            
            # Number of connected components
            metrics['num_components'] = nx.number_connected_components(G)
            
        except Exception as e:
            logger.warning(f"Graph analysis error: {e}")
            metrics = {'error': str(e)}
        
        return metrics
    
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk score into levels"""
        if risk_score < 0.3:
            return 'low'
        elif risk_score < 0.7:
            return 'medium'
        else:
            return 'high'


class DomainFeatureExtractor:
    """
    Extract features from domain information
    """
    
    def __init__(self):
        self.whois_cache = {}
        self.dns_cache = {}
    
    def extract_domain_features(self, domain: str) -> Dict[str, any]:
        """
        Extract comprehensive domain features
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Basic domain properties
        features.update(self._extract_basic_features(domain))
        
        # WHOIS information
        features.update(self._extract_whois_features(domain))
        
        # DNS records
        features.update(self._extract_dns_features(domain))
        
        # SSL certificate
        features.update(self._extract_ssl_features(domain))
        
        # Reputation and threat intelligence
        features.update(self._extract_reputation_features(domain))
        
        return features
    
    def _extract_basic_features(self, domain: str) -> Dict[str, any]:
        """Extract basic domain characteristics"""
        import tldextract
        
        extracted = tldextract.extract(domain)
        
        return {
            'domain_length': len(domain),
            'subdomain': extracted.subdomain,
            'domain_name': extracted.domain,
            'tld': extracted.suffix,
            'has_subdomain': bool(extracted.subdomain),
            'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            'has_hyphen': '-' in extracted.domain,
            'has_numbers': any(c.isdigit() for c in extracted.domain),
            'entropy': self._calculate_entropy(extracted.domain)
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counts = Counter(text)
        probs = [count / len(text) for count in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        
        return entropy
    
    def _extract_whois_features(self, domain: str) -> Dict[str, any]:
        """Extract WHOIS information"""
        try:
            import whois
            
            if domain in self.whois_cache:
                w = self.whois_cache[domain]
            else:
                w = whois.whois(domain)
                self.whois_cache[domain] = w
            
            # Calculate domain age
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = (datetime.now() - creation_date).days
            else:
                age = 0
            
            return {
                'age_days': age,
                'registrar': w.registrar,
                'whois_private': 'privacy' in str(w).lower() or 'redacted' in str(w).lower(),
                'has_creation_date': creation_date is not None,
                'has_expiration_date': w.expiration_date is not None
            }
        
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {
                'age_days': 0,
                'registrar': None,
                'whois_private': True,
                'has_creation_date': False,
                'has_expiration_date': False
            }
    
    def _extract_dns_features(self, domain: str) -> Dict[str, any]:
        """Extract DNS record information"""
        try:
            import dns.resolver
            
            features = {
                'has_a_record': False,
                'has_mx_record': False,
                'has_ns_record': False,
                'dns_records': 0,
                'ip_addresses': []
            }
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                features['has_a_record'] = True
                features['ip_addresses'] = [str(rdata) for rdata in answers]
                features['dns_records'] += len(answers)
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                features['has_mx_record'] = True
                features['dns_records'] += len(answers)
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                features['has_ns_record'] = True
                features['dns_records'] += len(answers)
            except:
                pass
            
            return features
        
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            return {
                'has_a_record': False,
                'has_mx_record': False,
                'has_ns_record': False,
                'dns_records': 0,
                'ip_addresses': []
            }
    
    def _extract_ssl_features(self, domain: str) -> Dict[str, any]:
        """Extract SSL certificate information"""
        import ssl
        import socket
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'ssl_valid': True,
                        'ssl_issuer': dict(x[0] for x in cert['issuer']),
                        'ssl_subject': dict(x[0] for x in cert['subject']),
                        'ssl_version': ssock.version()
                    }
        except Exception as e:
            logger.warning(f"SSL check failed for {domain}: {e}")
            return {
                'ssl_valid': False,
                'ssl_issuer': None,
                'ssl_subject': None,
                'ssl_version': None
            }
    
    def _extract_reputation_features(self, domain: str) -> Dict[str, any]:
        """Extract reputation scores"""
        # Placeholder for threat intelligence integration
        return {
            'reputation_score': 0.5,  # Default neutral
            'in_blocklist': False,
            'threat_score': 0.0,
            'country_risk_score': 0.5
        }


# Model factory
def create_gnn_model(
    input_dim: int = 128,
    hidden_dim: int = 256,
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
) -> GNNDomainAnalyzer:
    """
    Factory function to create GNN models
    
    Args:
        input_dim: Dimension of node features
        hidden_dim: Hidden layer dimension
        device: Device to load model on
        
    Returns:
        Initialized GNN model
    """
    model = GNNDomainAnalyzer(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=3
    )
    model.to(device)
    
    logger.info(f"GNN Model created on {device}")
    
    return model


if __name__ == "__main__":
    # Example usage
    print("Initializing GNN Domain Analysis Model...")
    
    model = create_gnn_model()
    feature_extractor = DomainFeatureExtractor()
    
    # Test domain analysis
    test_domain = "suspicious-paypal-verify.com"
    related = ["www.suspicious-paypal-verify.com", "login.suspicious-paypal-verify.com"]
    
    # Extract features
    features = {
        test_domain: feature_extractor.extract_domain_features(test_domain)
    }
    for rel_domain in related:
        features[rel_domain] = feature_extractor.extract_domain_features(rel_domain)
    
    # Analyze
    result = model.analyze_domain_network(
        domain=test_domain,
        related_domains=related,
        domain_features=features
    )
    
    print("\n=== Domain Network Analysis ===")
    print(f"Domain: {result['domain']}")
    print(f"Risk Score: {result['risk_score']:.2%}")
    print(f"Risk Level: {result['risk_level'].upper()}")
    print(f"Network Size: {result['network_size']} domains")
    print(f"Malicious: {'YES' if result['is_malicious'] else 'NO'}")
