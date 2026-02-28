from backend.storage.neo4j_client import neo4j_client


class RelationshipGraphBuilder:
    async def upsert_contact(self, sender: str, recipient: str, subject_hash: str, financial_keywords: bool) -> None:
        if not sender or not recipient:
            return
        try:
            await neo4j_client.create_domain_node(sender, {'kind': 'EmailAddress'})
            await neo4j_client.create_domain_node(recipient, {'kind': 'EmailAddress'})
            await neo4j_client.create_relationship(sender, recipient, 'SENT_TO')
        except Exception:
            return
