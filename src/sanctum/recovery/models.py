from enum import Enum
from typing import List, Optional, Tuple, Dict, Any
import hashlib
import json
from pydantic import BaseModel, Field


class RecoveryGrade(str, Enum):
    INTACT = "INTACT"
    PARTIAL = "PARTIAL"
    METADATA_ONLY = "METADATA_ONLY"
    CARVED = "CARVED"


class SourceProvenance(BaseModel):
    """Forensic provenance detailing exact origin and allocation status."""
    source_lba: int
    sector_count: int
    offset_bytes: int
    cluster_or_inode: int
    data_runs: List[Tuple[int, int]] = Field(default_factory=list)  # (start_lba, count)
    overwritten_clusters: List[int] = Field(default_factory=list)
    free_clusters: List[int] = Field(default_factory=list)


class RecoveredFile(BaseModel):
    """Represents a reconstructed deleted file."""
    file_id: str
    reconstructed_path: str
    original_name: str
    size_bytes: int
    grade: RecoveryGrade
    sha256: str
    validation_passed: bool
    validator_type: str
    provenance: SourceProvenance
    errors: List[str] = Field(default_factory=list)
    # The actual recovered payload can be serialized or stored
    data: Optional[bytes] = Field(default=None, exclude=True)


class CaseManifest(BaseModel):
    """Case manifest recording all reconstructed deleted artifacts."""
    case_id: str
    evidence_id: str
    source_serial: str
    timestamp: str
    total_recovered: int = 0
    intact_count: int = 0
    partial_count: int = 0
    metadata_only_count: int = 0
    carved_count: int = 0
    files: List[RecoveredFile] = Field(default_factory=list)
    manifest_sha256: str = ""

    def finalize(self) -> None:
        """Computes summary metrics and cryptographic manifest hash."""
        self.total_recovered = len(self.files)
        self.intact_count = sum(1 for f in self.files if f.grade == RecoveryGrade.INTACT)
        self.partial_count = sum(1 for f in self.files if f.grade == RecoveryGrade.PARTIAL)
        self.metadata_only_count = sum(1 for f in self.files if f.grade == RecoveryGrade.METADATA_ONLY)
        self.carved_count = sum(1 for f in self.files if f.grade == RecoveryGrade.CARVED)

        # Deterministic serialization for manifest SHA-256
        data_str = json.dumps(
            {
                "case_id": self.case_id,
                "evidence_id": self.evidence_id,
                "source_serial": self.source_serial,
                "timestamp": self.timestamp,
                "files": [f.model_dump(exclude={"data"}) for f in self.files],
            },
            sort_keys=True,
            default=str,
        )
        self.manifest_sha256 = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    def save_to_file(self, filepath: str) -> None:
        self.finalize()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))
