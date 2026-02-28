from backend.sms_service.sender_reputation import SenderReputationEngine


def test_sender_id_obfuscation():
    engine = SenderReputationEngine()
    result = engine.score_sender('Amaz0nHelp', carrier='unknown')
    assert 'score' in result
