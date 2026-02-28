import base64
from typing import Dict


class YARAScanner:
    def __init__(self):
        self._rules = None
        try:
            import yara
            source = """
            rule EmbeddedExecutable {
                strings:
                    $mz = {4D 5A}
                    $elf = {7F 45 4C 46}
                    $macro = /Auto(Open|Exec|Close)/ nocase
                condition:
                    any of them
            }
            """
            self._rules = yara.compile(source=source)
        except Exception:
            self._rules = None

    def scan_b64(self, content_b64: str) -> Dict:
        try:
            data = base64.b64decode(content_b64)
        except Exception:
            return {'malicious': False, 'matches': []}

        if not self._rules:
            return {'malicious': False, 'matches': []}

        matches = [m.rule for m in self._rules.match(data=data)]
        return {'malicious': bool(matches), 'matches': matches}
