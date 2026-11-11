import struct
import hashlib
import datetime
import logging
from typing import List, Optional, Dict, Tuple, Set
from sanctum.dal import BaseDevice
from sanctum.recovery.models import (
    RecoveryGrade,
    SourceProvenance,
    RecoveredFile,
    CaseManifest,
)
from sanctum.recovery.validator import ContentValidator

logger = logging.getLogger("sanctum.recovery.reconstructor")


def decode_ntfs_data_runs(runlist_bytes: bytes) -> List[Tuple[int, int]]:
    """
    Decodes NTFS non-resident data runs.
    Returns: List of (lcn_offset, cluster_count)
    """
    runs: List[Tuple[int, int]] = []
    offset = 0
    prev_lcn = 0

    while offset < len(runlist_bytes):
        header = runlist_bytes[offset]
        if header == 0x00:
            break
        offset += 1

        len_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F

        if offset + len_size + offset_size > len(runlist_bytes):
            break

        # Length (unsigned)
        len_bytes = runlist_bytes[offset : offset + len_size]
        run_len = int.from_bytes(len_bytes, byteorder="little", signed=False)
        offset += len_size

        # Offset (signed delta)
        off_bytes = runlist_bytes[offset : offset + offset_size]
        run_offset_delta = int.from_bytes(off_bytes, byteorder="little", signed=True)
        offset += offset_size

        current_lcn = prev_lcn + run_offset_delta
        runs.append((current_lcn, run_len))
        prev_lcn = current_lcn

    return runs


class DeletedFileReconstructor:
    """
    Forensic Reconstructor for deleted files across FAT, NTFS, and ext filesystems.
    Enforces:
    - Parent-path reconstruction with $OrphanFiles fallback
    - Cluster-chain contiguity inference
    - Allocation-bitmap overwrite verification
    - Structural content validation
    - Four-tier recovery grading (INTACT, PARTIAL, METADATA_ONLY, CARVED)
    - Full cryptographic provenance tracking
    """

    def __init__(self, device: BaseDevice, case_id: str = "CASE-2026", evidence_id: str = "ITEM-001"):
        self.device = device
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.sector_size = device.info.sector_size

    def reconstruct_from_fat(
        self,
        deleted_entries: List[Dict[str, Any]],
        allocated_clusters: Set[int],
        sec_per_cluster: int = 1,
        cluster_heap_start_lba: int = 32,
        parent_paths: Optional[Dict[int, str]] = None,
    ) -> List[RecoveredFile]:
        """
        Reconstructs deleted files discovered on FAT/exFAT media.
        deleted_entries format:
        [{"name": str, "first_cluster": int, "size": int, "parent_id": int}]
        """
        recovered: List[RecoveredFile] = []
        parent_paths = parent_paths or {}
        cluster_bytes = sec_per_cluster * self.sector_size

        for idx, entry in enumerate(deleted_entries, 1):
            name = entry.get("name", f"recovered_{idx}")
            first_cluster = entry.get("first_cluster", 0)
            file_size = entry.get("size", 0)
            parent_id = entry.get("parent_id")

            # 2. & 3. Parent-Path Reconstruction & $OrphanFiles fallback
            if parent_id in parent_paths and parent_paths[parent_id]:
                reconstructed_path = f"{parent_paths[parent_id]}/{name}".replace("//", "/")
            else:
                reconstructed_path = f"/$OrphanFiles/{name}"

            if first_cluster < 2 or file_size == 0:
                # Metadata-only recovery
                rec = RecoveredFile(
                    file_id=f"FAT_DEL_{idx}",
                    reconstructed_path=reconstructed_path,
                    original_name=name,
                    size_bytes=file_size,
                    grade=RecoveryGrade.METADATA_ONLY,
                    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of b""
                    validation_passed=False,
                    validator_type="NONE",
                    provenance=SourceProvenance(
                        source_lba=0,
                        sector_count=0,
                        offset_bytes=0,
                        cluster_or_inode=first_cluster,
                    ),
                    errors=["Zero file size or invalid starting cluster."],
                )
                recovered.append(rec)
                continue

            # 5. & 6. Cluster-chain reconstruction & contiguity inference
            clusters_needed = (file_size + cluster_bytes - 1) // cluster_bytes
            candidate_clusters = [first_cluster + c for c in range(clusters_needed)]

            # 7. Allocation-bitmap overwrite checking
            overwritten = [c for c in candidate_clusters if c in allocated_clusters]
            free = [c for c in candidate_clusters if c not in allocated_clusters]

            # Read reconstructed file data
            file_buf = bytearray()
            data_runs: List[Tuple[int, int]] = []

            for c in candidate_clusters:
                lba = cluster_heap_start_lba + (c - 2) * sec_per_cluster
                data_runs.append((lba, sec_per_cluster))
                for s in range(sec_per_cluster):
                    try:
                        file_buf.extend(self.device.read_sector(lba + s))
                    except Exception:
                        file_buf.extend(b"\x00" * self.sector_size)

            actual_data = bytes(file_buf[:file_size])
            data_sha256 = hashlib.sha256(actual_data).hexdigest()

            # 8. Content validation
            is_valid, v_type, v_notes = ContentValidator.validate(actual_data, filename=name)

            # 9. Recovery Grading
            if len(overwritten) == 0:
                if is_valid:
                    grade = RecoveryGrade.INTACT
                else:
                    grade = RecoveryGrade.PARTIAL
            elif len(overwritten) < len(candidate_clusters):
                grade = RecoveryGrade.PARTIAL
            else:
                grade = RecoveryGrade.METADATA_ONLY

            first_lba = cluster_heap_start_lba + (first_cluster - 2) * sec_per_cluster
            rec = RecoveredFile(
                file_id=f"FAT_DEL_{idx}",
                reconstructed_path=reconstructed_path,
                original_name=name,
                size_bytes=len(actual_data),
                grade=grade,
                sha256=data_sha256,
                validation_passed=is_valid and (grade == RecoveryGrade.INTACT),
                validator_type=v_type,
                provenance=SourceProvenance(
                    source_lba=first_lba,
                    sector_count=clusters_needed * sec_per_cluster,
                    offset_bytes=first_lba * self.sector_size,
                    cluster_or_inode=first_cluster,
                    data_runs=data_runs,
                    overwritten_clusters=overwritten,
                    free_clusters=free,
                ),
                data=actual_data,
                errors=[v_notes] if not is_valid else [],
            )
            recovered.append(rec)

        return recovered

    def reconstruct_from_ntfs_mft(
        self,
        deleted_records: List[Dict[str, Any]],
        allocated_clusters: Set[int],
        sec_per_cluster: int = 8,
        parent_paths: Optional[Dict[int, str]] = None,
    ) -> List[RecoveredFile]:
        """
        Reconstructs deleted files from unallocated NTFS MFT records.
        """
        recovered: List[RecoveredFile] = []
        parent_paths = parent_paths or {}
        cluster_bytes = sec_per_cluster * self.sector_size

        for idx, rec_info in enumerate(deleted_records, 1):
            name = rec_info.get("name", f"recovered_{idx}")
            parent_frn = rec_info.get("parent_frn")
            filesize = rec_info.get("filesize", 0)
            resident_data = rec_info.get("resident_data")
            runlist_bytes = rec_info.get("runlist_bytes")

            # Parent path reconstruction & orphan fallback
            if parent_frn in parent_paths and parent_paths[parent_frn]:
                reconstructed_path = f"{parent_paths[parent_frn]}/{name}".replace("//", "/")
            else:
                reconstructed_path = f"/$OrphanFiles/{name}"

            actual_data = b""
            overwritten: List[int] = []
            free: List[int] = []
            data_runs: List[Tuple[int, int]] = []
            start_lba = 0

            if resident_data is not None:
                # Resident $DATA
                actual_data = resident_data[:filesize]
            elif runlist_bytes:
                # 4. Data-run reconstruction
                decoded_runs = decode_ntfs_data_runs(runlist_bytes)
                buf = bytearray()
                for lcn, count in decoded_runs:
                    run_lba = lcn * sec_per_cluster
                    if start_lba == 0:
                        start_lba = run_lba
                    data_runs.append((run_lba, count * sec_per_cluster))

                    # Check cluster overwrite
                    for c_idx in range(lcn, lcn + count):
                        if c_idx in allocated_clusters:
                            overwritten.append(c_idx)
                        else:
                            free.append(c_idx)

                    for s in range(count * sec_per_cluster):
                        try:
                            buf.extend(self.device.read_sector(run_lba + s))
                        except Exception:
                            buf.extend(b"\x00" * self.sector_size)

                actual_data = bytes(buf[:filesize])

            data_sha256 = hashlib.sha256(actual_data).hexdigest()
            is_valid, v_type, v_notes = ContentValidator.validate(actual_data, filename=name)

            if len(actual_data) == 0:
                grade = RecoveryGrade.METADATA_ONLY
            elif len(overwritten) == 0:
                grade = RecoveryGrade.INTACT if is_valid else RecoveryGrade.PARTIAL
            elif len(overwritten) < len(free) + len(overwritten):
                grade = RecoveryGrade.PARTIAL
            else:
                grade = RecoveryGrade.METADATA_ONLY

            rec = RecoveredFile(
                file_id=f"NTFS_DEL_{idx}",
                reconstructed_path=reconstructed_path,
                original_name=name,
                size_bytes=len(actual_data),
                grade=grade,
                sha256=data_sha256,
                validation_passed=is_valid and (grade == RecoveryGrade.INTACT),
                validator_type=v_type,
                provenance=SourceProvenance(
                    source_lba=start_lba,
                    sector_count=(len(actual_data) + self.sector_size - 1) // self.sector_size,
                    offset_bytes=start_lba * self.sector_size,
                    cluster_or_inode=rec_info.get("mft_index", 0),
                    data_runs=data_runs,
                    overwritten_clusters=overwritten,
                    free_clusters=free,
                ),
                data=actual_data,
                errors=[v_notes] if not is_valid else [],
            )
            recovered.append(rec)

        return recovered

    def create_manifest(self, recovered_files: List[RecoveredFile]) -> CaseManifest:
        """
        11. Case-manifest recording: compiles and seals case manifest.
        """
        manifest = CaseManifest(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_serial=self.device.info.serial,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            files=recovered_files,
        )
        manifest.finalize()
        return manifest
