import abc
from typing import List


class BaseImageWriter(abc.ABC):
    """Abstract base class for forensic disk image writers."""

    @abc.abstractmethod
    def open(self) -> None:
        """Initialize and open the image writer."""
        pass

    @abc.abstractmethod
    def write_block(self, data: bytes) -> None:
        """Write a block of acquired data to the image stream."""
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Finalize and close the image files."""
        pass

    @abc.abstractmethod
    def get_segments(self) -> List[str]:
        """Return list of generated segment file paths."""
        pass

    @property
    @abc.abstractmethod
    def total_bytes_written(self) -> int:
        """Return total bytes written across all segments."""
        pass
