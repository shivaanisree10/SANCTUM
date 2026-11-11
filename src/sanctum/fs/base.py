import abc
import time
from typing import List, Optional, Set, Any
from sanctum.dal import BaseDevice
from sanctum.fs.models import FileEntry, FileMetadata, Extent

DEFAULT_MAX_RECURSION_DEPTH = 32
DEFAULT_MAX_ALLOC_BYTES = 64 * 1024 * 1024  # 64 MB maximum single buffer allocation
DEFAULT_PER_FILE_TIMEOUT = 2.0  # seconds


class FileSystemError(Exception):
    """Base exception for filesystem parsing errors."""
    pass


class ParserTimeoutError(FileSystemError):
    """Raised when parsing an individual file exceeds the allotted time limit."""
    pass


class ParserRecursionLimitError(FileSystemError):
    """Raised when directory traversal exceeds the safe recursion limit."""
    pass


class ParserCycleDetectedError(FileSystemError):
    """Raised when a circular reference or loop is detected in filesystem structures."""
    pass


class BaseFileSystemParser(abc.ABC):
    """
    Abstract Common Interface for all Forensic Filesystem Parsers.
    Enforces defensive constraints:
    - Bounded memory allocations
    - Cycle detection
    - Recursion depth limits
    - Per-file time limits
    - Parser error isolation
    """

    def __init__(
        self,
        device: BaseDevice,
        max_recursion_depth: int = DEFAULT_MAX_RECURSION_DEPTH,
        max_alloc_bytes: int = DEFAULT_MAX_ALLOC_BYTES,
        per_file_timeout: float = DEFAULT_PER_FILE_TIMEOUT,
    ):
        self.device = device
        self.max_recursion_depth = max_recursion_depth
        self.max_alloc_bytes = max_alloc_bytes
        self.per_file_timeout = per_file_timeout

    @classmethod
    @abc.abstractmethod
    def probe(cls, device: BaseDevice) -> float:
        """
        Inspects the device and returns a confidence score between 0.0 (unrecognized)
        and 1.0 (authoritative match).
        """
        pass

    @abc.abstractmethod
    def list_allocated(self) -> List[FileEntry]:
        """Returns all live/allocated files and directories."""
        pass

    @abc.abstractmethod
    def list_deleted(self) -> List[FileEntry]:
        """Returns deleted, orphaned, or carved files and directory entries."""
        pass

    @abc.abstractmethod
    def read_file_data(
        self, file_info: FileEntry, offset: int = 0, size: Optional[int] = None
    ) -> bytes:
        """Reads content bytes from the specified file entry with bounded limits."""
        pass

    @abc.abstractmethod
    def get_metadata(self, file_info: FileEntry) -> FileMetadata:
        """Retrieves detailed forensic metadata for a file entry."""
        pass

    @abc.abstractmethod
    def get_unallocated_extents(self) -> List[Extent]:
        """Extracts unallocated storage extents for carving and slack inspection."""
        pass

    # Defensive Helpers
    def check_recursion_depth(self, current_depth: int) -> None:
        """Enforces recursion limits on nested directories."""
        if current_depth > self.max_recursion_depth:
            raise ParserRecursionLimitError(
                f"Maximum recursion depth of {self.max_recursion_depth} exceeded."
            )

    def check_cycle(self, visited: Set[Any], node_id: Any) -> None:
        """Enforces cycle detection against corrupted filesystem loops."""
        if node_id in visited:
            raise ParserCycleDetectedError(
                f"Circular reference loop detected on node {node_id}."
            )
        visited.add(node_id)

    def clamp_allocation_size(self, requested_size: int) -> int:
        """Enforces bounded memory allocations to protect against malformed size headers."""
        if requested_size < 0:
            return 0
        return min(requested_size, self.max_alloc_bytes)

    def check_timeout(self, start_time: float) -> None:
        """Enforces per-file time limits."""
        if time.monotonic() - start_time > self.per_file_timeout:
            raise ParserTimeoutError(
                f"File processing exceeded per-file timeout limit of {self.per_file_timeout}s."
            )
