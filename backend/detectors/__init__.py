"""
Detection Modules Package
Contains all phishing detection implementations
"""

from .url_detector import PhishingShield2
from .sms_detector import SmishingShield
from .email_detector import EmailShield
from .image_detector import ImageShieldAdvanced

__all__ = [
    'PhishingShield2',
    'SmishingShield',
    'EmailShield',
    'ImageShieldAdvanced'
]
