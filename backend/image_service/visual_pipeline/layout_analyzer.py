import re


class LayoutAnalyzer:
    def analyze_layout(self, extracted_text: str) -> dict:
        lower = extracted_text.lower()
        has_user = bool(re.search(r'username|email|user id', lower))
        has_pass = bool(re.search(r'password|passcode', lower))
        has_signin = bool(re.search(r'sign in|login|verify', lower))
        confidence = 0.15 + 0.35 * has_user + 0.35 * has_pass + 0.15 * has_signin
        fake_login = confidence >= 0.65
        return {'is_fake_login_page': fake_login, 'layout_confidence': float(min(0.99, confidence))}
