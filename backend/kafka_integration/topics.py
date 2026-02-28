from ..api_gateway.config import settings

# Topic names
TOPIC_URL = settings.KAFKA_TOPIC_URL
TOPIC_SMS = settings.KAFKA_TOPIC_SMS
TOPIC_EMAIL = settings.KAFKA_TOPIC_EMAIL
TOPIC_IMAGE = settings.KAFKA_TOPIC_IMAGE
TOPIC_RESULTS = 'detection.results'
TOPIC_FEEDBACK = 'user.feedback'
TOPIC_IOC = 'ioc.updates'

# Topic configurations
TOPIC_CONFIGS = {
    TOPIC_URL: {'partitions': 12, 'replication_factor': 3},
    TOPIC_SMS: {'partitions': 6, 'replication_factor': 3},
    TOPIC_EMAIL: {'partitions': 6, 'replication_factor': 3},
    TOPIC_IMAGE: {'partitions': 6, 'replication_factor': 3},
    TOPIC_RESULTS: {'partitions': 12, 'replication_factor': 3},
    TOPIC_FEEDBACK: {'partitions': 3, 'replication_factor': 3},
    TOPIC_IOC: {'partitions': 3, 'replication_factor': 3},
}
