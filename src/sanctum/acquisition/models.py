from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
from pydantic import BaseModel, Field


class ImageFormat(str, Enum):
    RAW = "RAW"
    E01 = "E01"
    AFF4 = "AFF4"


class AcquisitionConfig(BaseModel):
    """Configuration for forensic disk acquisition."""
    output_path: str
    format: ImageFormat = ImageFormat.RAW
    segment_size_bytes: Optional[int] = None  # None = single file, e.g. 2GB = 2*1024*1024*1024
    block_size_bytes: int = 1024 * 64  # Default 64KB read block
    max_retries: int = 3
    case_id: str = "CASE-001"
    evidence_id: str = "ITEM-001"
    examiner: str = "FORENSIC-OPERATOR"
    description: str = "Physical Device Acquisition"


class ErrorRegion(BaseModel):
    """Represents a range of unreadable sectors substituted with zeros."""
    start_lba: int
    sector_count: int
    error_message: str


class ErrorMap(BaseModel):
    """Persistent mapping of defective or unreadable LBAs."""
    regions: List[ErrorRegion] = Field(default_factory=list)
    total_bad_sectors: int = 0
    total_bad_bytes: int = 0

    def add_error(self, start_lba: int, sector_count: int, error_message: str, sector_size: int = 512) -> None:
        self.regions.append(ErrorRegion(
            start_lba=start_lba,
            sector_count=sector_count,
            error_message=error_message
        ))
        self.total_bad_sectors += sector_count
        self.total_bad_bytes += (sector_count * sector_size)

    def save_to_file(self, filepath: str | Path) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

    @classmethod
    def load_from_file(cls, filepath: str | Path) -> "ErrorMap":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return cls(**data)


class AcquisitionMetadata(BaseModel):
    """Comprehensive forensic acquisition metadata."""
    acquisition_id: str
    case_id: str
    evidence_id: str
    examiner: str
    description: str
    timestamp_started: str
    timestamp_completed: str
    source_serial: str
    source_path: str
    source_capacity_bytes: int
    sector_size: int
    total_lbas: int
    format: ImageFormat
    segment_size_bytes: Optional[int]
    segments: List[str]
    pre_source_sha256: str
    post_source_sha256: str
    source_hashes_match: bool
    image_sha256: str
    streaming_acquisition_sha256: str
    image_verification_passed: bool
    write_counter_before: int
    write_counter_after: int
    write_counter_delta: int
    write_blocking_verified: bool
    total_bad_sectors: int
    total_bad_bytes: int
    error_map_file: Optional[str]


class AcquisitionResult(BaseModel):
    """Result of an acquisition run."""
    success: bool
    status: str  # SUCCESS, COMPLETED_WITH_ERRORS, FAILED
    metadata: AcquisitionMetadata
    error_map: ErrorMap
