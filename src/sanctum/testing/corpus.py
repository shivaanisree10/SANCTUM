import os
import hashlib
import struct
import io
import zipfile
from typing import Dict, Any, List
from pydantic import BaseModel


class CorpusItem(BaseModel):
    item_id: str
    name: str
    extension: str
    size_bytes: int
    expected_sha256: str
    category: str
    data_bytes: bytes


class KnownAnswerCorpus:
    """
    Known-Answer Test Corpus & Ground-Truth Database.
    Generates deterministic known-answer files across supported formats:
    - JPEG images with valid SOI/EOI
    - PNG images with standard headers & IEND chunk
    - PDF documents with %PDF- header and EOF
    - OOXML (DOCX/XLSX) zip packages
    - Structured text & JSON data
    """

    @classmethod
    def generate_jpeg(cls, name: str = "test_image.jpg", width: int = 16, height: int = 16) -> CorpusItem:
        # Minimal valid JPEG binary structure
        payload = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
            b"\xff\xdb\x00C\x00" + (b"\x08" * 64) +
            b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
            b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00"
            b"\xff\xd9"
        )
        sha256 = hashlib.sha256(payload).hexdigest()
        return CorpusItem(
            item_id="CORPUS-JPEG-001",
            name=name,
            extension="jpg",
            size_bytes=len(payload),
            expected_sha256=sha256,
            category="IMAGE",
            data_bytes=payload,
        )

    @classmethod
    def generate_png(cls, name: str = "test_graphic.png") -> CorpusItem:
        # Minimal valid 1x1 PNG
        payload = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
            b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        sha256 = hashlib.sha256(payload).hexdigest()
        return CorpusItem(
            item_id="CORPUS-PNG-001",
            name=name,
            extension="png",
            size_bytes=len(payload),
            expected_sha256=sha256,
            category="IMAGE",
            data_bytes=payload,
        )

    @classmethod
    def generate_pdf(cls, name: str = "evidence_doc.pdf") -> CorpusItem:
        payload = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
            b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
        )
        sha256 = hashlib.sha256(payload).hexdigest()
        return CorpusItem(
            item_id="CORPUS-PDF-001",
            name=name,
            extension="pdf",
            size_bytes=len(payload),
            expected_sha256=sha256,
            category="DOCUMENT",
            data_bytes=payload,
        )

    @classmethod
    def generate_docx(cls, name: str = "report.docx") -> CorpusItem:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
            z.writestr("word/document.xml", b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Confidential Report</w:t></w:r></w:p></w:body></w:document>')
        payload = buf.getvalue()
        sha256 = hashlib.sha256(payload).hexdigest()
        return CorpusItem(
            item_id="CORPUS-DOCX-001",
            name=name,
            extension="docx",
            size_bytes=len(payload),
            expected_sha256=sha256,
            category="DOCUMENT",
            data_bytes=payload,
        )

    @classmethod
    def get_ground_truth_catalog(cls) -> Dict[str, CorpusItem]:
        items = [
            cls.generate_jpeg(),
            cls.generate_png(),
            cls.generate_pdf(),
            cls.generate_docx(),
        ]
        return {item.item_id: item for item in items}
