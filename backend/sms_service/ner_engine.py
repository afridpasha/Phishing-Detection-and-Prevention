import re
from typing import List


class BrandNER:
    def __init__(self):
        self._nlp = None
        try:
            import spacy
            self._nlp = spacy.load('en_core_web_sm')
        except Exception:
            self._nlp = None
        self.brand_lexicon = {'paypal', 'google', 'microsoft', 'apple', 'amazon', 'usps', 'fedex', 'dhl', 'netflix', 'bank'}

    def extract_brands(self, message: str) -> List[str]:
        found = set()
        lower = message.lower()
        for brand in self.brand_lexicon:
            if re.search(rf'\b{re.escape(brand)}\b', lower):
                found.add(brand.upper())
        if self._nlp:
            doc = self._nlp(message)
            for ent in doc.ents:
                if ent.label_ in {'ORG', 'PRODUCT'}:
                    candidate = ent.text.strip().upper()
                    if candidate:
                        found.add(candidate)
        return sorted(found)
