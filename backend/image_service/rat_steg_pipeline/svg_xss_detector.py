try:
    from lxml import etree
except Exception:  # pragma: no cover
    etree = None
import re

class SVGXSSDetector:
    """Detect XSS vulnerabilities in SVG files"""
    
    def __init__(self):
        self.dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'onload=',
            r'onerror=',
            r'onclick=',
            r'onmouseover=',
            r'data:text/javascript',
            r'expression\(',
            r'<foreignObject'
        ]
    
    def detect(self, file_bytes: bytes) -> dict:
        """Detect XSS in SVG"""
        try:
            content = file_bytes.decode('utf-8', errors='ignore')
            
            # Check for dangerous patterns
            xss_found = False
            found_patterns = []
            
            for pattern in self.dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    xss_found = True
                    found_patterns.append(pattern)
            
            # Parse XML and check for script tags
            if etree is not None:
                try:
                    tree = etree.fromstring(file_bytes)
                    scripts = tree.findall('.//{http://www.w3.org/2000/svg}script')
                    if scripts:
                        xss_found = True
                        found_patterns.append('<script> tag found')
                except:
                    pass
            
            return {
                'svg_xss_found': xss_found,
                'patterns_detected': found_patterns,
                'payload': content[:500] if xss_found else None
            }
        except Exception as e:
            return {
                'svg_xss_found': False,
                'patterns_detected': [],
                'payload': None,
                'error': str(e)
            }
