from backend.image_service.file_analysis.polyglot_detector import PolyglotDetector


def test_jpeg_zip_polyglot():
    detector = PolyglotDetector()
    fake = b'\xff\xd8\xff' + b'A' * 1024 + b'PK\x05\x06'
    result = detector.detect(fake, 'jpg')
    assert result['is_polyglot'] is True


def test_png_pe_polyglot():
    detector = PolyglotDetector()
    fake = b'\x89PNG' + b'A' * 1024 + b'MZ'
    result = detector.detect(fake, 'png')
    assert result['is_polyglot'] is True
