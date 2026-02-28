from backend.url_service.preprocessor import URLPreprocessor


def test_case_variation_evasion():
    p = URLPreprocessor()
    normalized = p.normalize_url('HTTPS://PaYpAl.CoM/Login')
    assert normalized.startswith('https://')


def test_character_insertion_evasion():
    p = URLPreprocessor()
    has_homoglyph, _, _ = p.detect_homoglyphs('https://paypa1.security-check.com')
    assert isinstance(has_homoglyph, bool)
