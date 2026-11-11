import os
import time
import hashlib
import yaml
import logging
from typing import List, Optional, Dict, Set, Tuple
from pathlib import Path

from sanctum.dal import BaseDevice
from sanctum.carving.models import (
    FileSignature,
    CarvedFile,
    CarvingReport,
)
from sanctum.carving.entropy import calculate_entropy, classify_block
from sanctum.carving.matcher import AhoCorasickMatcher
from sanctum.carving.validators import VALIDATORS

logger = logging.getLogger("sanctum.carving.engine")


class CarvingEngine:
    """
    Forensic File Carving Engine.
    Executes streaming multi-pattern signature scanning, structure-aware validation,
    entropy-based block analysis, bifragment recovery, and cryptographic deduplication.
    """

    def __init__(
        self,
        config_path: str = "config/signatures.yaml",
        chunk_size_bytes: int = 1024 * 1024,  # 1 MB streaming chunk
    ):
        self.config_path = config_path
        self.chunk_size = chunk_size_bytes
        self.signatures: List[FileSignature] = []
        self.matcher = AhoCorasickMatcher()
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Loads signature definitions from signatures.yaml."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Signature database not found: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for item in data.get("signatures", []):
            sig = FileSignature(**item)
            self.signatures.append(sig)
            # Add header to Aho-Corasick matcher
            self.matcher.add_pattern(sig.header_bytes, sig)

        self.matcher.compile()
        logger.info(f"Loaded {len(self.signatures)} file signatures into Aho-Corasick matcher.")

    def carve_device(
        self,
        device: BaseDevice,
        time_budget_seconds: Optional[float] = None,
        max_files: Optional[int] = None,
    ) -> CarvingReport:
        """
        Scans device storage stream and extracts validated carved files.
        """
        start_time = time.monotonic()
        sector_size = device.info.sector_size
        total_bytes = device.info.capacity_bytes
        total_lbas = device.info.lba_count

        report = CarvingReport()
        seen_hashes: Set[str] = set()
        carved_files: List[CarvedFile] = []

        # Find max header size to calculate stream window overlap
        max_header_len = max(len(s.header_bytes) for s in self.signatures) if self.signatures else 64
        overlap_size = max_header_len + 16

        current_offset = 0
        timed_out = False
        file_id_counter = 1

        # Buffer read window
        chunk_lbas = max(1, self.chunk_size // sector_size)
        curr_lba = 0
        carryover = b""

        while curr_lba < total_lbas:
            if time_budget_seconds and (time.monotonic() - start_time) > time_budget_seconds:
                logger.warning("Global scan time budget reached. Stopping carving scan.")
                timed_out = True
                break

            # Read next chunk of sectors
            read_count = min(chunk_lbas, total_lbas - curr_lba)
            chunk_data = bytearray(carryover)

            for i in range(read_count):
                try:
                    chunk_data.extend(device.read_sector(curr_lba + i))
                except Exception:
                    chunk_data.extend(b"\x00" * sector_size)

            raw_window = bytes(chunk_data)
            window_base_offset = (curr_lba * sector_size) - len(carryover)
            report.total_scanned_bytes += (read_count * sector_size)

            # 1. Multi-pattern search on window using Aho-Corasick
            matches = self.matcher.search(raw_window)
            report.total_candidates += len(matches)

            for match_in_window, sig in matches:
                abs_match_offset = window_base_offset + match_in_window
                if abs_match_offset < 0:
                    continue

                # Adjust for header_offset if specified in signature (e.g. MP4 ftyp at offset 4)
                start_file_offset = abs_match_offset - sig.header_offset
                if start_file_offset < 0 or start_file_offset >= total_bytes:
                    continue

                # Fetch file data window up to sig.max_size
                candidate_data = self._read_device_slice(
                    device, start_file_offset, sig.max_size
                )
                if not candidate_data:
                    continue

                # 4. Embedded-length / 5. Footer / 7. Structure-aware validation
                validator_fn = VALIDATORS.get(sig.validator)
                if not validator_fn:
                    continue

                is_valid, extracted_len, notes = validator_fn(candidate_data)

                # 8. Fragment recovery check for JPEG (truncated or containing a gap)
                is_fragmented = False
                if sig.id == "JPEG":
                    has_gap = False
                    if is_valid and extracted_len > 1024:
                        extracted_slice = candidate_data[:extracted_len]
                        for g in range(512, len(extracted_slice) - 512, 512):
                            if set(extracted_slice[g : g + 512]) in ({0}, {0xFF}):
                                has_gap = True
                                break

                    if not is_valid or has_gap:
                        frag_data, frag_len = self._attempt_jpeg_fragment_recovery(
                            candidate_data
                        )
                        if frag_data:
                            v_ok, v_len, v_notes = validator_fn(frag_data)
                            if v_ok:
                                candidate_data = frag_data
                                is_valid = True
                                extracted_len = v_len
                                is_fragmented = True
                                notes = v_notes + " [Bifragment Spliced Recovery]"

                if not is_valid:
                    continue

                # Finalize extracted byte slice
                final_length = extracted_len if (extracted_len > 0 and extracted_len <= len(candidate_data)) else min(len(candidate_data), sig.max_size)
                carved_bytes = candidate_data[:final_length]

                # 9. Content-hash deduplication
                data_sha256 = hashlib.sha256(carved_bytes).hexdigest()
                if data_sha256 in seen_hashes:
                    report.deduplicated_count += 1
                    continue
                seen_hashes.add(data_sha256)

                # 10. Source-offset provenance
                start_lba = start_file_offset // sector_size
                entropy = calculate_entropy(carved_bytes)

                carved = CarvedFile(
                    id=f"CARVED_{file_id_counter:04d}",
                    format_id=sig.id,
                    extension=sig.extension,
                    start_byte_offset=start_file_offset,
                    start_lba=start_lba,
                    size_bytes=len(carved_bytes),
                    sha256=data_sha256,
                    validation_passed=True,
                    validator_notes=notes,
                    is_fragmented=is_fragmented,
                    entropy=entropy,
                    data=carved_bytes,
                )
                carved_files.append(carved)
                file_id_counter += 1

                if max_files and len(carved_files) >= max_files:
                    break

            if max_files and len(carved_files) >= max_files:
                break

            # Carry over boundary overlap bytes
            carryover = raw_window[-overlap_size:] if len(raw_window) >= overlap_size else raw_window
            curr_lba += read_count

        elapsed = time.monotonic() - start_time
        report.elapsed_seconds = elapsed
        report.timed_out = timed_out
        report.carved_files = carved_files
        report.valid_carved_count = len(carved_files)

        logger.info(
            f"Carving completed: {len(carved_files)} valid file(s) carved in {elapsed:.2f}s "
            f"(deduplicated {report.deduplicated_count})."
        )
        return report

    def _read_device_slice(self, device: BaseDevice, start_offset: int, max_length: int) -> bytes:
        """Reads a byte slice from device starting at byte offset."""
        sector_size = device.info.sector_size
        total_bytes = device.info.capacity_bytes
        safe_len = min(max_length, total_bytes - start_offset)
        if safe_len <= 0:
            return b""

        start_lba = start_offset // sector_size
        end_lba = (start_offset + safe_len + sector_size - 1) // sector_size
        offset_in_first_sector = start_offset % sector_size

        buf = bytearray()
        for lba in range(start_lba, end_lba):
            try:
                buf.extend(device.read_sector(lba))
            except Exception:
                buf.extend(b"\x00" * sector_size)

        return bytes(buf[offset_in_first_sector : offset_in_first_sector + safe_len])

    def _attempt_jpeg_fragment_recovery(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """
        Bifragment gap detection and recovery for fragmented JPEGs.
        Scans for an entropy collapse / gap (e.g. cluster wipe or slack)
        followed by a resumed high-entropy fragment containing EOI \xFF\xD9.
        """
        if len(data) < 1024 or not data.startswith(b"\xff\xd8\xff"):
            return None, 0

        # Scan for an all-zero or low-entropy gap of at least 512 bytes
        gap_start = -1
        gap_end = -1
        sector_size = 512

        for i in range(512, min(len(data) - 512, 1048576), sector_size):
            chunk = data[i : i + sector_size]
            if set(chunk) == {0} or set(chunk) == {0xFF}:
                gap_start = i
                # Find where valid high-entropy resumption starts
                j = i + sector_size
                while j + sector_size <= len(data):
                    resumed_chunk = data[j : j + sector_size]
                    if calculate_entropy(resumed_chunk) > 2.0 and set(resumed_chunk) not in ({0}, {0xFF}):
                        gap_end = j
                        break
                    j += sector_size
                break

        if gap_start != -1 and gap_end != -1:
            frag1 = data[:gap_start]
            frag2 = data[gap_end:]
            spliced = frag1 + frag2
            if b"\xff\xd9" in spliced:
                eoi_pos = spliced.find(b"\xff\xd9")
                final_spliced = spliced[: eoi_pos + 2]
                return final_spliced, len(final_spliced)

        return None, 0
