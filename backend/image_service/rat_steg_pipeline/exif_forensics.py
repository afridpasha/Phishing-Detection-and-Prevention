try:
    import exifread
except Exception:  # pragma: no cover
    exifread = None
import re

class EXIFForensics:
    """Analyze EXIF data for malware signatures"""
    
    def __init__(self):
        self.suspicious_patterns = [
            b'MZ',  # PE header
            b'\x7fELF',  # ELF header
            b'<?php',  # PHP code
            b'<script',  # JavaScript
            b'\x89PNG',  # PNG in EXIF
            b'\xff\xd8\xff',  # JPEG in EXIF
        ]
    
    def analyze(self, file_bytes: bytes) -> dict:
        """Analyze EXIF for malware"""
        try:
            if exifread is None:
                return {
                    'exif_malware_found': False,
                    'suspicious_fields': [],
                    'total_tags': 0,
                }
            import io
            tags = exifread.process_file(io.BytesIO(file_bytes), details=False)
            
            malware_found = False
            suspicious_fields = []
            
            # Check each EXIF field
            for tag, value in tags.items():
                value_bytes = str(value).encode('utf-8', errors='ignore')
                
                # Check for suspicious patterns
                for pattern in self.suspicious_patterns:
                    if pattern in value_bytes:
                        malware_found = True
                        suspicious_fields.append({
                            'field': tag,
                            'pattern': pattern.decode('utf-8', errors='ignore'),
                            'value_preview': str(value)[:100]
                        })
            
            # Check for unusually long fields
            for tag, value in tags.items():
                if len(str(value)) > 1000:
                    malware_found = True
                    suspicious_fields.append({
                        'field': tag,
                        'reason': 'Unusually long field',
                        'length': len(str(value))
                    })
            
            return {
                'exif_malware_found': malware_found,
                'suspicious_fields': suspicious_fields,
                'total_tags': len(tags)
            }
        except Exception as e:
            return {
                'exif_malware_found': False,
                'suspicious_fields': [],
                'total_tags': 0,
                'error': str(e)
            }
