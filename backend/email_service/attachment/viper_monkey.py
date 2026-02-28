import base64
import re
from typing import Dict


class ViperMonkeyAnalyzer:
    def analyze_b64(self, content_b64: str, filename: str) -> Dict:
        try:
            data = base64.b64decode(content_b64)
        except Exception:
            return {'has_macro': False, 'macro_indicators': []}

        text = data.decode('utf-8', errors='ignore')
        indicators = []
        for pattern in [r'Auto(Open|Exec|Close)', r'CreateObject\(', r'Shell\(', r'WScript\.Shell']:
            if re.search(pattern, text, flags=re.IGNORECASE):
                indicators.append(pattern)

        has_macro = filename.lower().endswith(('.docm', '.xlsm', '.pptm')) or bool(indicators)
        return {'has_macro': has_macro, 'macro_indicators': indicators}
