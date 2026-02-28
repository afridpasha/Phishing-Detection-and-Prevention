import math
from collections import Counter

class EntropyAnalyzer:
    """Analyze file entropy to detect encrypted/compressed payloads"""
    
    def analyze(self, file_bytes: bytes) -> dict:
        """Calculate Shannon entropy for different file regions"""
        total_entropy = self._calculate_entropy(file_bytes)
        
        # Analyze different regions
        header_entropy = self._calculate_entropy(file_bytes[:512])
        middle_entropy = self._calculate_entropy(file_bytes[len(file_bytes)//2:len(file_bytes)//2+512])
        
        # Check for data after image end markers
        tail_entropy = 0.0
        suspicious_tail = False
        
        # JPEG end marker
        if b'\xff\xd9' in file_bytes:
            eoi_pos = file_bytes.rfind(b'\xff\xd9')
            if eoi_pos < len(file_bytes) - 100:  # Data after EOI
                tail_data = file_bytes[eoi_pos+2:]
                tail_entropy = self._calculate_entropy(tail_data)
                if tail_entropy > 7.5:
                    suspicious_tail = True
        
        # PNG end marker
        if b'IEND' in file_bytes:
            iend_pos = file_bytes.rfind(b'IEND')
            if iend_pos < len(file_bytes) - 100:
                tail_data = file_bytes[iend_pos+8:]
                tail_entropy = self._calculate_entropy(tail_data)
                if tail_entropy > 7.5:
                    suspicious_tail = True
        
        return {
            'total_entropy': total_entropy,
            'header_entropy': header_entropy,
            'middle_entropy': middle_entropy,
            'tail_entropy': tail_entropy,
            'suspicious_tail': suspicious_tail,
            'likely_encrypted': total_entropy > 7.2
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
