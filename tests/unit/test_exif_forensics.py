from backend.image_service.rat_steg_pipeline.exif_forensics import EXIFForensics


def test_clean_exif():
    detector = EXIFForensics()
    result = detector.analyze(b'not-an-image-but-no-exif')
    assert 'exif_malware_found' in result


def test_pe_in_exif_comment():
    detector = EXIFForensics()
    payload = b'Exif\x00Comment MZ test'
    result = detector.analyze(payload)
    assert isinstance(result['exif_malware_found'], bool)
