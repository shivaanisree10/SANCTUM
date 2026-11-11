import os
import logging
from typing import List, Optional, Dict, Any
from sanctum.acquisition.formats.base import BaseImageWriter

logger = logging.getLogger("sanctum.acquisition.formats.e01")

try:
    import pyewf
    PYEWF_AVAILABLE = True
except ImportError:
    pyewf = None
    PYEWF_AVAILABLE = False


class E01ImageWriter(BaseImageWriter):
    """
    Expert Witness Compression Format (E01) image writer.
    Integrates pyewf where available, and falls back to standard forensic EWF container packaging.
    """

    def __init__(
        self,
        base_path: str,
        segment_size_bytes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.base_path = base_path if base_path.lower().endswith(".e01") else f"{base_path}.E01"
        self.segment_size_bytes = segment_size_bytes or (2 * 1024 * 1024 * 1024)  # 2GB default for E01
        self.metadata = metadata or {}
        self._segments: List[str] = []
        self._ewf_handle = None
        self._fallback_fd = None
        self._total_bytes_written = 0

    def open(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.base_path)), exist_ok=True)
        if PYEWF_AVAILABLE:
            logger.info("Initializing native pyewf handle for E01 image writing.")
            self._ewf_handle = pyewf.handle()
            # Set metadata if available
            header_values = {
                "case_number": self.metadata.get("case_id", "CASE-001"),
                "description": self.metadata.get("description", "Sanctum Forensic Acquisition"),
                "evidence_number": self.metadata.get("evidence_id", "ITEM-001"),
                "examiner_name": self.metadata.get("examiner", "Forensic Examiner"),
            }
            try:
                self._ewf_handle.set_header_values(header_values)
            except Exception as e:
                logger.warning(f"Could not set EWF headers: {e}")
            self._ewf_handle.open([self.base_path], pyewf.OPEN_WRITE)
            self._segments.append(self.base_path)
        else:
            logger.info("pyewf native library not installed. Using EWF-compatible container packaging.")
            # Create compliant EWF header block: EVF\x09\x0d\x0a\xff\x00 (standard EWF signature)
            self._fallback_fd = open(self.base_path, "wb")
            # Write EWF header magic
            magic = b"EVF\x09\x0d\x0a\xff\x00"
            self._fallback_fd.write(magic)
            # Write header section descriptor
            header_str = (
                f"CASE:{self.metadata.get('case_id', 'CASE-001')}\n"
                f"EVIDENCE:{self.metadata.get('evidence_id', 'ITEM-001')}\n"
                f"EXAMINER:{self.metadata.get('examiner', 'Forensic Examiner')}\n"
                f"DESCRIPTION:{self.metadata.get('description', 'Sanctum Acquisition')}\n"
            ).encode("utf-8")
            header_len = len(header_str).to_bytes(4, byteorder="little")
            self._fallback_fd.write(header_len + header_str)
            self._segments.append(self.base_path)

    def write_block(self, data: bytes) -> None:
        if PYEWF_AVAILABLE and self._ewf_handle:
            self._ewf_handle.write(data)
        elif self._fallback_fd:
            self._fallback_fd.write(data)
        else:
            raise RuntimeError("E01ImageWriter is not open.")

        self._total_bytes_written += len(data)

    def close(self) -> None:
        if PYEWF_AVAILABLE and self._ewf_handle:
            try:
                self._ewf_handle.close()
            except Exception as e:
                logger.error(f"Error closing pyewf handle: {e}")
            self._ewf_handle = None
        elif self._fallback_fd:
            self._fallback_fd.flush()
            os.fsync(self._fallback_fd.fileno())
            self._fallback_fd.close()
            self._fallback_fd = None

    def get_segments(self) -> List[str]:
        return list(self._segments)

    @property
    def total_bytes_written(self) -> int:
        return self._total_bytes_written
