import os
from typing import List, Optional
from sanctum.acquisition.formats.base import BaseImageWriter


class RawImageWriter(BaseImageWriter):
    """
    Forensic Raw / DD disk image writer.
    Supports single file (.raw / .dd / .img) or split segmented images (.001, .002, ...).
    """

    def __init__(self, base_path: str, segment_size_bytes: Optional[int] = None):
        self.base_path = base_path
        self.segment_size_bytes = segment_size_bytes
        self._segments: List[str] = []
        self._current_segment_idx = 0
        self._current_fd = None
        self._current_segment_bytes = 0
        self._total_bytes_written = 0

    def _get_segment_path(self, index: int) -> str:
        if self.segment_size_bytes is None:
            return self.base_path
        # Format as e.g. path.001, path.002
        return f"{self.base_path}.{index:03d}"

    def _open_next_segment(self) -> None:
        if self._current_fd:
            self._current_fd.flush()
            os.fsync(self._current_fd.fileno())
            self._current_fd.close()

        self._current_segment_idx += 1
        seg_path = self._get_segment_path(self._current_segment_idx)
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(seg_path)), exist_ok=True)
        self._current_fd = open(seg_path, "wb")
        self._segments.append(seg_path)
        self._current_segment_bytes = 0

    def open(self) -> None:
        self._open_next_segment()

    def write_block(self, data: bytes) -> None:
        if not self._current_fd:
            raise RuntimeError("RawImageWriter is not open.")

        if self.segment_size_bytes is None:
            self._current_fd.write(data)
            self._total_bytes_written += len(data)
            return

        # Handle writing data across segment boundaries
        offset = 0
        total_len = len(data)
        while offset < total_len:
            space_left = self.segment_size_bytes - self._current_segment_bytes
            if space_left <= 0:
                self._open_next_segment()
                space_left = self.segment_size_bytes

            chunk_len = min(total_len - offset, space_left)
            chunk = data[offset : offset + chunk_len]
            self._current_fd.write(chunk)
            self._current_segment_bytes += chunk_len
            self._total_bytes_written += chunk_len
            offset += chunk_len

    def close(self) -> None:
        if self._current_fd:
            self._current_fd.flush()
            os.fsync(self._current_fd.fileno())
            self._current_fd.close()
            self._current_fd = None

    def get_segments(self) -> List[str]:
        return list(self._segments)

    @property
    def total_bytes_written(self) -> int:
        return self._total_bytes_written
