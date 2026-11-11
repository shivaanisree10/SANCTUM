import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class CaseState(str, Enum):
    CREATED = "CREATED"
    OPEN = "OPEN"
    ATTACH_EXHIBIT = "ATTACH_EXHIBIT"
    PROCESS = "PROCESS"
    CLOSED = "CLOSED"


class RecoveryGrade(str, Enum):
    INTACT = "Intact"
    PARTIAL = "Partial"
    METADATA_ONLY = "Metadata-only"
    CARVED = "Carved"


class CaseRecord(BaseModel):
    case_id: str
    case_number: str
    title: str
    investigator: str
    agency: Optional[str] = None
    state: CaseState = CaseState.CREATED
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    closed_at: Optional[str] = None
    notes: Optional[str] = None


class ExhibitRecord(BaseModel):
    exhibit_id: str
    case_id: str
    exhibit_number: str
    description: str
    device_serial: Optional[str] = None
    received_from: Optional[str] = None
    received_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    storage_location: Optional[str] = None
    status: str = "SECURED"


class DeviceRecord(BaseModel):
    device_id: str
    case_id: Optional[str] = None
    exhibit_id: Optional[str] = None
    serial: str
    model: Optional[str] = None
    vendor: Optional[str] = None
    capacity_bytes: int = 0
    wwn: Optional[str] = None
    interface: Optional[str] = None
    is_forensic_hold: bool = True
    added_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class JobRecord(BaseModel):
    job_id: str
    case_id: str
    job_type: str  # ACQUISITION, CARVING, TIMELINE, RECOVERY, VERIFICATION
    device_serial: Optional[str] = None
    status: str = "PENDING"
    started_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    summary: Optional[str] = None


class ImageRecord(BaseModel):
    image_id: str
    case_id: str
    exhibit_id: Optional[str] = None
    format: str  # RAW, E01, AFF4
    file_path: str
    size_bytes: int = 0
    sha256_hash: str
    source_serial: str
    segment_count: int = 1
    acquired_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class RecoveredObjectRecord(BaseModel):
    object_id: str
    case_id: str
    exhibit_id: Optional[str] = None
    name: str
    extension: str
    size_bytes: int
    sha256_hash: str
    recovery_grade: RecoveryGrade
    source_offset: int
    source_lba: int = 0
    provenance: str
    metadata_json: Optional[str] = None
    recovered_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class CustodyEntryRecord(BaseModel):
    entry_id: str
    case_id: str
    exhibit_id: str
    timestamp_utc: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    action: str  # SEIZED, RECEIVED, TRANSFERRED, CHECKED_OUT, CHECKED_IN, EXAMINED, ARCHIVED
    actor: str
    source_holder: str
    target_holder: str
    reason: str
    prev_record_hash: str
    record_hash: str = ""
    notes: Optional[str] = None


class CertificateRecord(BaseModel):
    certificate_id: str
    case_id: Optional[str] = None
    certificate_type: str  # DESTRUCTION, VERIFICATION, ACQUISITION
    device_serial: str
    result: str  # PASS, FAIL
    method: str
    sha256_hash: str
    signature: str
    issued_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    payload_json: str = "{}"
