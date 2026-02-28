from minio import Minio

from backend.api_gateway.config import settings


class MinIOClient:
    def __init__(self):
        self.client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=False,
        )

    def ensure_bucket(self, bucket: str) -> None:
        if not self.client.bucket_exists(bucket):
            self.client.make_bucket(bucket)

    def upload_bytes(self, bucket: str, object_name: str, data: bytes, content_type: str = 'application/octet-stream'):
        import io

        self.ensure_bucket(bucket)
        self.client.put_object(bucket, object_name, io.BytesIO(data), len(data), content_type=content_type)

    def get_presigned_url(self, bucket: str, object_name: str):
        try:
            return self.client.presigned_get_object(bucket, object_name)
        except Exception:
            return None


minio_client = MinIOClient()
