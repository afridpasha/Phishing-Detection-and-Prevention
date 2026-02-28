from typing import Dict

from backend.ensemble_engine.meta_learner import predict_meta_score


async def make_final_decision(input_type: str, model_scores: Dict[str, float], metadata: Dict, indicators: list) -> Dict:
    final_score, _ = predict_meta_score(input_type, model_scores, metadata)

    emergency_flags = [
        bool(metadata.get('is_polyglot')),
        bool(metadata.get('c2_beacons_detected')),
        bool(metadata.get('svg_xss_found')),
        bool(metadata.get('exif_malware_found')),
    ]

    if any(emergency_flags):
        return {
            'final_score': max(final_score, 0.95),
            'risk_level': 'critical',
            'action': 'emergency_block',
            'confidence': 0.98,
            'summary': 'Critical payload risk detected. Emergency block enforced.',
            'recommendation': 'Block immediately and isolate source.',
        }

    if final_score < 0.35:
        risk_level, action, confidence = 'safe', 'allow', 0.95
    elif final_score < 0.55:
        risk_level, action, confidence = 'low', 'allow', 0.85
    elif final_score < 0.70:
        risk_level, action, confidence = 'medium', 'warn', 0.75
    elif final_score < 0.85:
        risk_level, action, confidence = 'high', 'block', 0.85
    else:
        risk_level, action, confidence = 'critical', 'block', 0.95

    if risk_level in {'high', 'critical'}:
        summary = f'Critical phishing threat detected (score: {final_score:.2f})'
        recommendation = 'Block immediately. Do not proceed.'
    elif risk_level == 'medium':
        summary = f'Suspicious activity detected (score: {final_score:.2f})'
        recommendation = 'Proceed with caution and verify source.'
    else:
        summary = f'No significant threats detected (score: {final_score:.2f})'
        recommendation = 'Safe to proceed.'

    return {
        'final_score': float(final_score),
        'risk_level': risk_level,
        'action': action,
        'confidence': float(confidence),
        'summary': summary,
        'recommendation': recommendation,
    }
