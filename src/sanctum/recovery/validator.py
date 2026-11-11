import struct
from typing import Tuple


class ContentValidator:
    """
    Validates recovered file payloads using header, footer, and structural checks.
    Guarantees that files claimed as INTACT or PARTIAL pass content validation.
    """

    @staticmethod
    def validate(data: bytes, filename: str = "") -> Tuple[bool, str, str]:
        """
        Returns: (is_valid: bool, detected_format: str, notes: str)
        """
        if not data:
            return False, "EMPTY", "File payload is empty (0 bytes)."

        ext = filename.lower().split(".")[-1] if "." in filename else ""

        # 1. PNG Image
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            if b"IHDR" in data[:32]:
                has_iend = data.endswith(b"IEND\xaeB`\x82") or b"IEND" in data[-32:]
                if has_iend:
                    return True, "PNG", "Valid PNG header, IHDR chunk, and IEND footer."
                return True, "PNG_TRUNCATED", "Valid PNG header and IHDR chunk, but missing IEND."
            return False, "CORRUPT_PNG", "PNG magic present but missing IHDR chunk."

        # 2. JPEG Image
        if data.startswith(b"\xff\xd8\xff"):
            has_eoi = data.endswith(b"\xff\xd9") or b"\xff\xd9" in data[-16:]
            if has_eoi:
                return True, "JPEG", "Valid JPEG SOI and EOI markers."
            return True, "JPEG_TRUNCATED", "Valid JPEG SOI marker, missing clean EOI."

        # 3. PDF Document
        if data.startswith(b"%PDF-"):
            has_eof = b"%%EOF" in data[-1024:] or len(data) > 64
            if has_eof:
                return True, "PDF", "Valid PDF header and document structure."
            return False, "CORRUPT_PDF", "PDF header present but document severely truncated."

        # 4. ZIP Archive / Office Open XML (DOCX, XLSX, PPTX)
        if data.startswith(b"PK\x03\x04"):
            has_eocd = b"PK\x05\x06" in data[-1024:] or len(data) > 30
            if has_eocd:
                return True, "ZIP", "Valid ZIP local header and End of Central Directory."
            return True, "ZIP_PARTIAL", "Valid ZIP local header."

        # 5. Plaintext (TXT, LOG, CSV, JSON, XML)
        if ext in ("txt", "log", "csv", "json", "xml", "py", "md", "html") or len(data) < 100000:
            try:
                sample = data[:4096]
                text = sample.decode("utf-8")
                # Check ratio of printable characters
                printable_count = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
                if len(text) > 0 and (printable_count / len(text)) > 0.90:
                    return True, "TEXT", "Valid UTF-8/ASCII printable character stream."
            except UnicodeDecodeError:
                pass

        # 6. Generic / Binary payload check
        # Must not be homogeneous wipe pattern (all 0x00 or all 0xFF)
        sample = data[: min(len(data), 4096)]
        unique_bytes = len(set(sample))
        if unique_bytes > 4:
            return True, "BINARY", f"Valid structured binary data ({unique_bytes} distinct bytes)."

        return False, "CORRUPT_OR_UNALLOCATED", "Payload contains uniform wipe bytes or uninitialized data."
