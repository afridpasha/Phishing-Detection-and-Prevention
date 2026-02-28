import re
from typing import Dict


class HTMLDeobfuscator:
    def extract_indicators(self, html: str | None) -> Dict:
        if not html:
            return {'urls': [], 'hidden_links': 0, 'iframe_count': 0, 'script_count': 0}
        urls = re.findall(r"https?://[^\"'\\s<>]+", html, flags=re.IGNORECASE)
        hidden_links = len(re.findall(r'display\s*:\s*none|visibility\s*:\s*hidden', html, flags=re.IGNORECASE))
        iframe_count = len(re.findall(r'<iframe', html, flags=re.IGNORECASE))
        script_count = len(re.findall(r'<script', html, flags=re.IGNORECASE))
        return {'urls': sorted(set(urls)), 'hidden_links': hidden_links, 'iframe_count': iframe_count, 'script_count': script_count}
