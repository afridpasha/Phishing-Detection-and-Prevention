import base64
from email import policy
from email.parser import BytesParser
from typing import Dict, List


class MIMEParser:
    def parse(self, raw_message: bytes) -> Dict:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        text_parts: List[str] = []
        html_parts: List[str] = []
        attachments: List[Dict] = []

        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            content_type = (part.get_content_type() or '').lower()
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b''

            if filename:
                attachments.append({'filename': filename, 'mime_type': content_type, 'content_b64': base64.b64encode(payload).decode('ascii')})
                continue

            text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            if content_type == 'text/plain':
                text_parts.append(text)
            elif content_type == 'text/html':
                html_parts.append(text)

        return {
            'subject': str(msg.get('subject', '')),
            'sender_email': str(msg.get('from', '')),
            'recipient_email': str(msg.get('to', '')),
            'headers_raw': str(msg),
            'body_text': '\n'.join(text_parts).strip(),
            'body_html': '\n'.join(html_parts).strip() if html_parts else None,
            'attachments': attachments,
        }
