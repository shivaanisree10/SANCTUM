from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class PartitionScheme(str, Enum):
    MBR = "MBR"
    GPT = "GPT"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class PartitionEntry(BaseModel):
    """Represents a single partition on a disk."""
    index: int
    name: str = "Partition"
    type_id: str  # Hex ID (e.g. "0x07") or GUID string
    start_lba: int
    end_lba: int
    sector_count: int
    size_bytes: int
    bootable: bool = False
    is_extended: bool = False
    is_logical: bool = False
    fs_type: Optional[str] = None
    is_valid: bool = True
    notes: List[str] = Field(default_factory=list)


class PartitionMap(BaseModel):
    """Complete in-memory model of a disk's partition layout and health."""
    scheme: PartitionScheme
    total_disk_lbas: int
    sector_size: int = 512
    partitions: List[PartitionEntry] = Field(default_factory=list)
    is_consistent: bool = True
    overlaps: List[str] = Field(default_factory=list)
    capacity_violations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    is_repaired: bool = False
    repair_notes: List[str] = Field(default_factory=list)
