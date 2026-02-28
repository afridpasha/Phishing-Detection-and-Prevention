import pytest
from backend.image_service.rat_steg_pipeline.svg_xss_detector import SVGXSSDetector

@pytest.fixture
def detector():
    return SVGXSSDetector()

def test_clean_svg(detector):
    """Test clean SVG returns no XSS"""
    clean_svg = b'''<?xml version="1.0"?>
    <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
        <circle cx="50" cy="50" r="40" fill="blue"/>
    </svg>'''
    result = detector.detect(clean_svg)
    assert result['svg_xss_found'] == False

def test_script_tag_svg(detector):
    """Test SVG with script tag is detected"""
    malicious_svg = b'''<?xml version="1.0"?>
    <svg xmlns="http://www.w3.org/2000/svg">
        <script>alert('XSS')</script>
    </svg>'''
    result = detector.detect(malicious_svg)
    assert result['svg_xss_found'] == True

def test_javascript_href_svg(detector):
    """Test SVG with javascript: href is detected"""
    malicious_svg = b'''<?xml version="1.0"?>
    <svg xmlns="http://www.w3.org/2000/svg">
        <a href="javascript:alert('XSS')">Click</a>
    </svg>'''
    result = detector.detect(malicious_svg)
    assert result['svg_xss_found'] == True

def test_onload_handler_svg(detector):
    """Test SVG with onload handler is detected"""
    malicious_svg = b'''<?xml version="1.0"?>
    <svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
    </svg>'''
    result = detector.detect(malicious_svg)
    assert result['svg_xss_found'] == True
