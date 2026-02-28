import pytest
import numpy as np
from PIL import Image
import io
from backend.image_service.rat_steg_pipeline.lsb_analyzer import LSBAnalyzer

@pytest.fixture
def analyzer():
    return LSBAnalyzer()

def create_test_image(size=(100, 100)):
    """Create a test image"""
    img = Image.new('RGB', size, color='white')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    return img_bytes.getvalue()

def test_clean_image_chi_square(analyzer):
    """Test that clean image has high p-value"""
    image_bytes = create_test_image()
    result = analyzer.analyze(image_bytes)
    assert result['chi_square_pvalue'] > 0.05
    assert result['steganography_detected'] == False

def test_rs_analysis_clean(analyzer):
    """Test RS ratio for clean images"""
    image_bytes = create_test_image()
    result = analyzer.analyze(image_bytes)
    assert result['rs_ratio'] < 1.8

def test_analyzer_handles_invalid_image(analyzer):
    """Test analyzer handles invalid image gracefully"""
    invalid_bytes = b'not an image'
    result = analyzer.analyze(invalid_bytes)
    assert 'error' in result or result['steganography_detected'] == False
