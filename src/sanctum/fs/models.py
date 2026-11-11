from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FileEntryType(str, Enum):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    SPECIAL = "SPECIAL"


class Extent(BaseModel):
    """Represents a contiguous storage run on the underlying storage."""
    start_lba: int
    sector_count: int
    offset_bytes: int
    size_bytes: int


class FileMetadata(BaseModel):
    """Forensic metadata associated with a file or directory."""
    size_bytes: int = 0
    mtime: Optional[str] = None  # Modification time
    atime: Optional[str] = None  # Access time
    ctime: Optional[str] = None  # Metadata change time
    crtime: Optional[str] = None  # Creation / Birth time
    mode: Optional[int] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    extents: List[Extent] = Field(default_factory=list)
    sha256: Optional[str] = None


class FileEntry(BaseModel):
    """Represents a file, directory, or deleted artifact."""
    id: str
    path: str
    name: str
    entry_type: FileEntryType
    is_deleted: bool = False
    size_bytes: int = 0
    metadata: Optional[FileMetadata] = None
    errors: List[str] = Field(default_factory=list)
    # Internal payload or reference used by parsers
    internal_ref: Optional[Dict[str, Any]] = None
