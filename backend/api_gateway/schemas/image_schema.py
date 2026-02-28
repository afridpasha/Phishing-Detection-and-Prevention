from pydantic import BaseModel, Field
from typing import Optional, List
from .common_schema import DetectionResult

class ImageMetadata(BaseModel):
    file_type_detected: str
    file_size_bytes: int
    is_polyglot: bool
    steganography_detected: bool
    steg_method: Optional[str] = None
    steg_confidence: float
    chi_square_pvalue: float
    svg_xss_found: bool
    exif_malware_found: bool
    qr_codes_found: int
    qr_decoded_urls: List[str]
    brands_detected: List[str]
    brand_impersonation_score: float
    is_fake_login_page: bool
    layout_confidence: float
    text_extracted: str
    rat_family_suspected: Optional[str] = None
    sandbox_detonated: bool
    c2_beacons_detected: bool
    c2_domains: List[str]

class ImageAnalysisResponse(DetectionResult):
    metadata: ImageMetadata
