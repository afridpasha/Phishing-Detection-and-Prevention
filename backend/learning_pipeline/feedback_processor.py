from typing import Dict

from backend.learning_pipeline.river_online_learner import online_learner
from backend.storage.postgres_client import postgres_client


class FeedbackProcessor:
    def __init__(self):
        self._feedback_log = {}

    async def process_feedback(self, feedback: Dict):
        request_id = feedback["request_id"]
        is_correct = feedback["is_correct"]
        actual_label = feedback.get("actual_label")
        row = None

        try:
            if not postgres_client.pool:
                await postgres_client.connect()

            if postgres_client.pool:
                async with postgres_client.pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE detection_results
                        SET is_correct = $1, feedback_text = $2
                        WHERE request_id = $3
                        """,
                        is_correct,
                        feedback.get("comments"),
                        request_id,
                    )
                    row = await conn.fetchrow(
                        """
                        SELECT model_scores, metadata
                        FROM detection_results
                        WHERE request_id = $1
                        """,
                        request_id,
                    )
        except Exception:
            row = None

        self._feedback_log[request_id] = dict(feedback)

        updated = False
        if row and actual_label is not None:
            model_scores = row["model_scores"] or {}
            metadata = row["metadata"] or {}
            features = {
                **model_scores,
                **{k: v for k, v in metadata.items() if isinstance(v, (int, float, bool))},
            }
            try:
                online_learner.update(features, int(actual_label))
                updated = True
            except Exception:
                updated = False

        return {"status": "success", "updated": updated, "stored": "memory"}


feedback_processor = FeedbackProcessor()
