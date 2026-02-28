import pytest
from backend.url_service.preprocessor import URLPreprocessor

@pytest.fixture
def preprocessor():
    return URLPreprocessor()

def test_unicode_normalization(preprocessor):
    """Test punycode decoding"""
    url = "https://xn--pypal-4ve.com/login"
    normalized = preprocessor.normalize_url(url)
    assert 'xn--' not in normalized or normalized != url

def test_homoglyph_detection(preprocessor):
    """Test homoglyph detection for paypa1.com"""
    url = "https://paypa1.com/login"
    has_homoglyph, brand, confidence = preprocessor.detect_homoglyphs(url)
    assert has_homoglyph == True
    assert brand == "paypal"
    assert confidence > 0.8

def test_ip_detection(preprocessor):
    """Test IP address detection in URL"""
    url = "http://192.168.1.1/login"
    has_ip = preprocessor.has_ip_address(url)
    assert has_ip == True

def test_legitimate_url(preprocessor):
    """Test legitimate URL has no homoglyphs"""
    url = "https://google.com"
    has_homoglyph, brand, confidence = preprocessor.detect_homoglyphs(url)
    assert has_homoglyph == False

@pytest.mark.asyncio
async def test_redirect_unwinding(preprocessor):
    """Test redirect chain unwinding"""
    url = "https://google.com"
    final_url, redirect_count, chain = await preprocessor.unwind_redirects(url)
    assert isinstance(redirect_count, int)
    assert len(chain) >= 1
