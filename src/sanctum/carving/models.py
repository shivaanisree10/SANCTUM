from enum import Enum
from typing import List, Optional, Tuple, Dict, Any
from pydantic import BaseModel, Field


class BlockEntropyClass(str, Enum):
    SPARSE_ZERO = "SPARSE_ZERO"
    LOW_TEXT_CODE = "LOW_TEXT_CODE"
    HIGH_COMPRESSED_MEDIA = "HIGH_COMPRESSED_MEDIA"


class FileSignature(BaseModel):
    """External file signature definition."""
    id: str
    name: str
    header: str  # Hex string, e.g. "FF D8 FF"
    header_bytes: bytes = b""
    header_offset: int = 0
    footer: Optional[str] = None
    footer_bytes: Optional[bytes] = None
    max_size: int = 20971520
    validator: str
    extension: str

    def model_post_init(self, __context: Any) -> None:
        self.header_bytes = bytes.fromhex(self.header.replace(" ", ""))
        if self.footer:
            self.footer_bytes = bytes.fromhex(self.footer.replace(" ", ""))


class CarvedFile(BaseModel):
    """Represents a validated carved file artifact."""
    id: str
    format_id: str
    extension: str
    start_byte_offset: int
    start_lba: int
    size_bytes: int
    sha256: str
    validation_passed: bool
    validator_notes: str
    is_fragmented: bool = False
    entropy: float = 0.0
    data: Optional[bytes] = Field(default=None, exclude=True)


class CarvingReport(BaseModel):
    """Execution report from a carving run."""
    total_scanned_bytes: int = 0
    total_candidates: int = 0
    valid_carved_count: int = 0
    deduplicated_count: int = 0
    elapsed_seconds: float = 0.0
    timed_out: bool = False
    carved_files: List[CarvedFile] = Field(default_factory=list)
