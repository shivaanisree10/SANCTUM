import os
import zipfile
import logging
from typing import List, Optional, Dict, Any
from sanctum.acquisition.formats.base import BaseImageWriter

logger = logging.getLogger("sanctum.acquisition.formats.aff4")

try:
    import pyaff4
    PYAFF4_AVAILABLE = True
except ImportError:
    pyaff4 = None
    PYAFF4_AVAILABLE = False


class AFF4ImageWriter(BaseImageWriter):
    """
    Advanced Forensic Format 4 (AFF4) image writer.
    Integrates pyaff4 where practical, and provides standard AFF4 ZIP/RDF container packaging.
    """

    def __init__(
        self,
        base_path: str,
        segment_size_bytes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.base_path = base_path if base_path.lower().endswith(".aff4") else f"{base_path}.aff4"
        self.metadata = metadata or {}
        self._segments: List[str] = []
        self._zip_file: Optional[zipfile.ZipFile] = None
        self._stream_handle = None
        self._total_bytes_written = 0

    def open(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.base_path)), exist_ok=True)
        logger.info(f"Creating AFF4 container at {self.base_path}")
        self._zip_file = zipfile.ZipFile(self.base_path, mode="w", compression=zipfile.ZIP_DEFLATED)
        
        # Write AFF4 specification version
        self._zip_file.writestr("version.txt", "AFF4 Specification 1.0\r\n")

        # Generate RDF Turtle metadata
        case_id = self.metadata.get("case_id", "CASE-001")
        evidence_id = self.metadata.get("evidence_id", "ITEM-001")
        examiner = self.metadata.get("examiner", "Forensic Examiner")
        serial = self.metadata.get("source_serial", "UNKNOWN-DISK")
        turtle_content = (
            f"@prefix aff4: <http://aff4.org/Schema#> .\n"
            f"@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n"
            f"<aff4://sanctum/{evidence_id}> a aff4:DiskImage ;\n"
            f"    aff4:caseNumber \"{case_id}\" ;\n"
            f"    aff4:evidenceNumber \"{evidence_id}\" ;\n"
            f"    aff4:examiner \"{examiner}\" ;\n"
            f"    aff4:deviceSerial \"{serial}\" ;\n"
            f"    aff4:category \"ForensicAcquisition\" .\n"
        )
        self._zip_file.writestr("information.turtle", turtle_content)

        # Open stream inside zip for raw block data
        self._stream_handle = self._zip_file.open("data.raw", mode="w")
        self._segments.append(self.base_path)

    def write_block(self, data: bytes) -> None:
        if not self._stream_handle:
            raise RuntimeError("AFF4ImageWriter is not open.")

        self._stream_handle.write(data)
        self._total_bytes_written += len(data)

    def close(self) -> None:
        if self._stream_handle:
            self._stream_handle.close()
            self._stream_handle = None

        if self._zip_file:
            self._zip_file.close()
            self._zip_file = None

    def get_segments(self) -> List[str]:
        return list(self._segments)

    @property
    def total_bytes_written(self) -> int:
        return self._total_bytes_written
