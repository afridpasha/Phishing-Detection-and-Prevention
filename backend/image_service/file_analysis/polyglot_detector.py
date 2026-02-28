try:
    import magic
except Exception:  # pragma: no cover
    magic = None

class PolyglotDetector:
    """Detect polyglot files (e.g., JPEG+ZIP, PNG+PE)"""
    
    def __init__(self):
        self.magic = magic.Magic(mime=True) if magic is not None else None
    
    def detect(self, file_bytes: bytes, claimed_extension: str) -> dict:
        """Detect if file is a polyglot"""
        # Detect actual file type
        try:
            actual_type = self.magic.from_buffer(file_bytes) if self.magic is not None else 'unknown'
        except:
            actual_type = "unknown"
        
        # Map extensions to MIME types
        ext_map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'svg': 'image/svg+xml',
            'pdf': 'application/pdf'
        }
        
        expected_type = ext_map.get(claimed_extension.lower(), 'unknown')
        
        # Check for type mismatch
        is_polyglot = False
        polyglot_types = []
        
        if actual_type != expected_type and expected_type != 'unknown':
            is_polyglot = True
            polyglot_types.append(actual_type)
        
        # Check for ZIP signature at end (JPEG+ZIP)
        if file_bytes.endswith(b'PK\x05\x06'):
            is_polyglot = True
            polyglot_types.append('ZIP_appended')
        
        # Check for PE header (MZ signature)
        if b'MZ' in file_bytes[512:]:  # Skip first 512 bytes
            is_polyglot = True
            polyglot_types.append('PE_embedded')
        
        # Check for ELF header
        if b'\x7fELF' in file_bytes[512:]:
            is_polyglot = True
            polyglot_types.append('ELF_embedded')
        
        return {
            'is_polyglot': is_polyglot,
            'actual_type': actual_type,
            'expected_type': expected_type,
            'polyglot_types': polyglot_types
        }
