import pytest

from backend.ensemble_engine.decision_maker import make_final_decision


@pytest.mark.asyncio
async def test_emergency_block_trigger():
    decision = await make_final_decision(
        input_type='image',
        model_scores={'clip_brand': 0.2, 'layoutlm': 0.2},
        metadata={'is_polyglot': True, 'c2_beacons_detected': False},
        indicators=['polyglot payload'],
    )
    assert decision['action'] == 'emergency_block'
    assert decision['risk_level'] == 'critical'
