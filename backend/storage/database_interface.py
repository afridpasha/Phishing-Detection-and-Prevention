"""
Database Interface Layer
Real-Time Phishing Detection System

Unified interface for all database operations (PostgreSQL, Neo4j, Redis)
"""

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False
    
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
from typing import Dict, List, Optional, Any
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Unified database management interface
    
    Supports:
    - PostgreSQL: Relational data (decisions, users, logs)
    - Neo4j: Graph data (domain relationships)
    - Redis: Caching and session management
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.postgres_pool = None
        self.neo4j_driver = None
        self.redis_client = None
    
    async def initialize(self):
        """Initialize all database connections"""
        await self._init_postgres()
        self._init_neo4j()
        await self._init_redis()
        logger.info("All database connections initialized")
    
    async def _init_postgres(self):
        """Initialize PostgreSQL connection pool"""
        if not ASYNCPG_AVAILABLE:
            logger.warning("asyncpg not installed. PostgreSQL features disabled.")
            return
        
        try:
            self.postgres_pool = await asyncpg.create_pool(
                host=self.config.get('postgres_host', 'localhost'),
                port=self.config.get('postgres_port', 5432),
                user=self.config.get('postgres_user', 'phishing_user'),
                password=self.config.get('postgres_password', 'phishing_pass'),
                database=self.config.get('postgres_db', 'phishing_db'),
                min_size=5,
                max_size=20
            )
            logger.info("PostgreSQL connection pool created")
        except Exception as e:
            logger.error(f"PostgreSQL initialization error: {e}")
    
    def _init_neo4j(self):
        """Initialize Neo4j driver"""
        if not NEO4J_AVAILABLE:
            logger.warning("neo4j not installed. Graph database features disabled.")
            return
        
        try:
            self.neo4j_driver = GraphDatabase.driver(
                self.config.get('neo4j_uri', 'bolt://localhost:7687'),
                auth=(
                    self.config.get('neo4j_user', 'neo4j'),
                    self.config.get('neo4j_password', 'phishing123')
                )
            )
            logger.info("Neo4j driver initialized")
        except Exception as e:
            logger.error(f"Neo4j initialization error: {e}")
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            logger.warning("redis not installed. Caching features disabled.")
            return
        
        try:
            self.redis_client = await redis.from_url(
                self.config.get('redis_url', 'redis://localhost:6379'),
                encoding='utf-8',
                decode_responses=True
            )
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Redis initialization error: {e}")
    
    # PostgreSQL Operations
    
    async def save_decision(self, decision: Dict[str, Any]) -> int:
        """
        Save phishing detection decision to PostgreSQL
        
        Returns:
            Decision ID
        """
        if not self.postgres_pool:
            logger.warning("PostgreSQL not available")
            return -1
        
        query = """
            INSERT INTO decisions (
                timestamp, final_score, risk_level, action,
                confidence, metadata, explanation
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        """
        
        async with self.postgres_pool.acquire() as conn:
            decision_id = await conn.fetchval(
                query,
                datetime.fromisoformat(decision['timestamp']),
                decision['final_score'],
                decision['risk_level'],
                decision['action'],
                decision['confidence'],
                json.dumps(decision.get('metadata', {})),
                json.dumps(decision.get('explanation', {}))
            )
        
        return decision_id
    
    async def get_decisions(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """Retrieve decisions from PostgreSQL"""
        if not self.postgres_pool:
            logger.warning("PostgreSQL not available")
            return []
        
        query = "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
        
        async with self.postgres_pool.acquire() as conn:
            rows = await conn.fetch(query, limit, offset)
            return [dict(row) for row in rows]
    
    async def save_user_feedback(
        self,
        decision_id: int,
        is_correct: bool,
        comments: Optional[str] = None
    ):
        """Save user feedback for retraining"""
        if not self.postgres_pool:
            logger.warning("PostgreSQL not available")
            return
        
        query = """
            INSERT INTO user_feedback (decision_id, is_correct, comments, timestamp)
            VALUES ($1, $2, $3, $4)
        """
        
        async with self.postgres_pool.acquire() as conn:
            await conn.execute(
                query,
                decision_id,
                is_correct,
                comments,
                datetime.now()
            )
        
        logger.info(f"User feedback saved for decision {decision_id}")
    
    # Neo4j Operations (Graph Database)
    
    def create_domain_node(self, domain: str, properties: Dict):
        """Create domain node in Neo4j"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available")
            return
        
        with self.neo4j_driver.session() as session:
            session.run(
                """
                MERGE (d:Domain {name: $domain})
                SET d += $properties
                SET d.updated_at = datetime()
                """,
                domain=domain,
                properties=properties
            )
    
    def create_domain_relationship(
        self,
        domain1: str,
        domain2: str,
        relationship_type: str
    ):
        """Create relationship between domains"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available")
            return
        
        with self.neo4j_driver.session() as session:
            session.run(
                f"""
                MATCH (d1:Domain {{name: $domain1}})
                MATCH (d2:Domain {{name: $domain2}})
                MERGE (d1)-[r:{relationship_type}]->(d2)
                SET r.created_at = datetime()
                """,
                domain1=domain1,
                domain2=domain2
            )
    
    def get_domain_network(self, domain: str, depth: int = 2) -> List[Dict]:
        """Get domain network from Neo4j"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available")
            return []
        
        with self.neo4j_driver.session() as session:
            result = session.run(
                """
                MATCH path = (d:Domain {name: $domain})-[*1..$depth]-(related:Domain)
                RETURN d, related, relationships(path)
                LIMIT 100
                """,
                domain=domain,
                depth=depth
            )
            
            return [record.data() for record in result]
    
    # Redis Operations (Cache)
    
    async def cache_threat_data(
        self,
        key: str,
        data: Dict,
        ttl: int = 3600
    ):
        """Cache threat intelligence data"""
        if not self.redis_client:
            logger.warning("Redis not available")
            return
        
        await self.redis_client.setex(
            key,
            ttl,
            json.dumps(data)
        )
    
    async def get_cached_threat_data(self, key: str) -> Optional[Dict]:
        """Retrieve cached threat data"""
        if not self.redis_client:
            return None
        
        data = await self.redis_client.get(key)
        return json.loads(data) if data else None
    
    async def cache_model_prediction(
        self,
        url_hash: str,
        prediction: Dict,
        ttl: int = 300
    ):
        """Cache model predictions"""
        if not self.redis_client:
            logger.warning("Redis not available")
            return
        
        await self.redis_client.setex(
            f"prediction:{url_hash}",
            ttl,
            json.dumps(prediction)
        )
    
    async def get_cached_prediction(self, url_hash: str) -> Optional[Dict]:
        """Get cached prediction"""
        if not self.redis_client:
            return None
        
        data = await self.redis_client.get(f"prediction:{url_hash}")
        return json.loads(data) if data else None
    
    # Cleanup
    
    async def close(self):
        """Close all database connections"""
        if self.postgres_pool:
            await self.postgres_pool.close()
            logger.info("PostgreSQL connection pool closed")
        
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Neo4j driver closed")
        
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")


# SQL Schema definitions
POSTGRES_SCHEMA = """
-- Decisions table
CREATE TABLE IF NOT EXISTS decisions (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    final_score FLOAT NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    metadata JSONB,
    explanation JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_decisions_timestamp ON decisions(timestamp);
CREATE INDEX idx_decisions_risk_level ON decisions(risk_level);

-- User feedback table
CREATE TABLE IF NOT EXISTS user_feedback (
    id SERIAL PRIMARY KEY,
    decision_id INTEGER REFERENCES decisions(id),
    is_correct BOOLEAN NOT NULL,
    comments TEXT,
    timestamp TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_feedback_decision ON user_feedback(decision_id);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    api_key VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value TEXT NOT NULL,
    source VARCHAR(100) NOT NULL,
    severity VARCHAR(20),
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    metadata JSONB,
    UNIQUE(indicator_type, indicator_value, source)
);

CREATE INDEX idx_threat_indicator ON threat_intelligence(indicator_type, indicator_value);
"""


if __name__ == "__main__":
    import asyncio
    
    async def main():
        print("Testing Database Manager...")
        
        config = {
            'postgres_host': 'localhost',
            'postgres_port': 5432,
            'postgres_user': 'phishing_user',
            'postgres_password': 'phishing_pass',
            'postgres_db': 'phishing_db',
            'neo4j_uri': 'bolt://localhost:7687',
            'neo4j_user': 'neo4j',
            'neo4j_password': 'phishing123',
            'redis_url': 'redis://localhost:6379'
        }
        
        db = DatabaseManager(config)
        await db.initialize()
        
        # Test cache
        await db.cache_threat_data('test_key', {'test': 'data'}, ttl=60)
        cached = await db.get_cached_threat_data('test_key')
        print(f"Cached data: {cached}")
        
        await db.close()
        print("Database manager test completed")
    
    asyncio.run(main())
