from enum import Enum
from typing import List, Optional, Dict, Any, Union
import json
import csv
from pydantic import BaseModel, Field


class TimestampType(str, Enum):
    # Standard MACB
    MODIFIED = "MODIFIED"          # 'M'
    ACCESSED = "ACCESSED"          # 'A'
    CHANGED = "CHANGED"            # 'C' (Metadata/MFT/Inode change)
    BIRTH = "BIRTH"                # 'B' (Creation / File birth)

    # Embedded Application Metadata Timestamps
    EXIF_TAKEN = "EXIF_TAKEN"
    EXIF_DIGITIZED = "EXIF_DIGITIZED"
    GPS_TIMESTAMP = "GPS_TIMESTAMP"
    OFFICE_CREATED = "OFFICE_CREATED"
    OFFICE_MODIFIED = "OFFICE_MODIFIED"
    PDF_CREATED = "PDF_CREATED"
    PDF_MODIFIED = "PDF_MODIFIED"
    ID3_RELEASE = "ID3_RELEASE"
    ZONE_DOWNLOAD = "ZONE_DOWNLOAD"


class TimestampRecord(BaseModel):
    """Normalized timestamp preserving raw value, raw format, and timezone provenance."""
    ts_type: TimestampType
    normalized_utc: str             # ISO 8601 UTC string (e.g. "2026-10-19T14:30:00Z")
    raw_value: Union[int, float, str]
    raw_format: str                 # "FILETIME", "UNIX_EPOCH", "DOS_DATETIME", "EXIF_STRING", "PDF_DATE"
    timezone_info: Optional[str] = None
    is_local_time: bool = False


class NTFSTimestampSet(BaseModel):
    """Preserves both $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN) timestamp sets."""
    standard_info: Dict[str, TimestampRecord] = Field(default_factory=dict)
    file_name: Dict[str, TimestampRecord] = Field(default_factory=dict)
    is_timestomped: bool = False
    timestomp_notes: List[str] = Field(default_factory=list)


class AlternateDataStream(BaseModel):
    """Represents an NTFS Alternate Data Stream (ADS)."""
    stream_name: str
    size_bytes: int
    zone_identifier: Optional[Dict[str, str]] = None  # ZoneId, HostUrl, ReferrerUrl


class ExtractedMetadata(BaseModel):
    """Comprehensive forensic metadata sidecar model."""
    artefact_id: str
    artefact_name: str
    source_path: str
    source_offset_bytes: int = 0
    source_lba: int = 0
    ntfs_timestamps: Optional[NTFSTimestampSet] = None
    filesystem_timestamps: List[TimestampRecord] = Field(default_factory=list)
    exif: Dict[str, Any] = Field(default_factory=dict)
    gps: Dict[str, Any] = Field(default_factory=dict)
    office_properties: Dict[str, Any] = Field(default_factory=dict)
    pdf_metadata: Dict[str, Any] = Field(default_factory=dict)
    id3: Dict[str, Any] = Field(default_factory=dict)
    alternate_data_streams: List[AlternateDataStream] = Field(default_factory=list)

    def save_sidecar(self, filepath: str) -> None:
        """Stores metadata in a sidecar manifest JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))


class TimelineEvent(BaseModel):
    """Individual event in a unified forensic timeline."""
    event_id: str
    timestamp_utc: str
    timestamp_type: str
    source_artefact: str
    source_offset: int
    source_lba: int
    description: str
    confidence: float = 1.0
    details: Dict[str, Any] = Field(default_factory=dict)


class ForensicTimeline(BaseModel):
    """Unified chronological timeline of all forensic events."""
    case_id: str = "CASE-2026"
    evidence_id: str = "ITEM-001"
    events: List[TimelineEvent] = Field(default_factory=list)

    def sort_events(self) -> None:
        """Sorts all timeline events chronologically."""
        self.events.sort(key=lambda e: e.timestamp_utc)

    def export_csv(self, filepath: str) -> None:
        """Exports timeline in standard forensic CSV format."""
        self.sort_events()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "EventID",
                "TimestampUTC",
                "Type",
                "SourceArtefact",
                "SourceOffset",
                "SourceLBA",
                "Description",
                "Details",
            ])
            for e in self.events:
                writer.writerow([
                    e.event_id,
                    e.timestamp_utc,
                    e.timestamp_type,
                    e.source_artefact,
                    e.source_offset,
                    e.source_lba,
                    e.description,
                    json.dumps(e.details),
                ])

    def export_json(self, filepath: str) -> None:
        """Exports timeline in machine-readable JSON format."""
        self.sort_events()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))
