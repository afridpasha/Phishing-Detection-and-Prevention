import re
from typing import Dict


class HeaderAnalyzer:
    def analyze(self, headers_raw: str, sender_email: str, sender_display_name: str | None = None) -> Dict:
        lower = (headers_raw or '').lower()

        def _extract_result(name: str) -> str:
            m = re.search(rf'{name}\s*=\s*(pass|fail|neutral|softfail|none)', lower)
            return m.group(1) if m else 'none'

        spf = _extract_result('spf')
        dkim = _extract_result('dkim')
        dmarc = _extract_result('dmarc')

        mismatch = False
        if sender_display_name:
            display = sender_display_name.lower()
            domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ''
            mismatch = bool(domain and (domain.split('.')[0] not in display))

        reply_to_mismatch = False
        m = re.search(r'^reply-to:\s*(.+)$', headers_raw or '', flags=re.IGNORECASE | re.MULTILINE)
        if m and sender_email:
            reply_to_mismatch = sender_email.lower() not in m.group(1).strip().lower()

        return {
            'spf_result': spf,
            'dkim_result': dkim,
            'dmarc_result': dmarc,
            'display_name_mismatch': mismatch,
            'reply_to_mismatch': reply_to_mismatch,
        }
