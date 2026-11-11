import hashlib
import struct
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.recovery import (
    RecoveryGrade,
    RecoveredFile,
    CaseManifest,
    ContentValidator,
    decode_ntfs_data_runs,
    DeletedFileReconstructor,
)


def create_blank_disk(path: Path, sector_count: int = 2048) -> None:
    with open(path, "wb") as f:
        f.seek(sector_count * 512 - 1)
        f.write(b"\x00")


# =========================================================================
# 1. KNOWN-ANSWER CORPUS & GROUND-TRUTH TESTS (FAT)
# =========================================================================


def test_fat_known_answer_recovery_and_hash_comparison(tmp_path: Path) -> None:
    disk_path = tmp_path / "fat_recovery_corpus.img"
    create_blank_disk(disk_path, sector_count=1024)

    # Known-answer Ground Truth Files:
    # 1. Intact Text file: "SECRET FORENSIC REPORT CONTENT\n"
    ground_truth_text = b"SECRET FORENSIC REPORT CONTENT\n"
    expected_text_hash = hashlib.sha256(ground_truth_text).hexdigest()

    # 2. Intact PNG image file
    ground_truth_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa" + (b"\x00" * 32) + b"IEND\xaeB`\x82"
    expected_png_hash = hashlib.sha256(ground_truth_png).hexdigest()

    # 3. Partial file (overwritten)
    ground_truth_doc = b"CONFIDENTIAL CASE EVIDENCE DETAILS" + (b"A" * 600)

    # Cluster size = 512 bytes (1 sector/cluster). Cluster 2 starts at LBA 32.
    # Write ground-truth text to cluster 2 (LBA 32)
    # Write ground-truth png to cluster 3 (LBA 33)
    # Write doc to cluster 4 and 5 (LBA 34 and 35)
    with open(disk_path, "r+b") as f:
        # Cluster 2
        f.seek(32 * 512)
        f.write(ground_truth_text)
        # Cluster 3
        f.seek(33 * 512)
        f.write(ground_truth_png)
        # Cluster 4 and 5
        f.seek(34 * 512)
        f.write(ground_truth_doc[:512])
        f.seek(35 * 512)
        f.write(b"OVERWRITTEN CLUSTER CONTENT BY NEW FILE")  # Cluster 5 was overwritten!

    vdev = VirtualDevice(disk_path)
    # Source hash before recovery
    source_pre_hash = hashlib.sha256(disk_path.read_bytes()).hexdigest()

    # Active allocation bitmap / allocated clusters set:
    # Cluster 5 is currently allocated to an active file! Cluster 2, 3, 4 are free.
    allocated_clusters = {5}

    deleted_entries = [
        {
            "name": "REPORT.TXT",
            "first_cluster": 2,
            "size": len(ground_truth_text),
            "parent_id": 10,
        },
        {
            "name": "LOGO.PNG",
            "first_cluster": 3,
            "size": len(ground_truth_png),
            "parent_id": 999,  # Unresolvable parent -> $OrphanFiles
        },
        {
            "name": "DOC.BIN",
            "first_cluster": 4,
            "size": len(ground_truth_doc),
            "parent_id": 10,
        },
        {
            "name": "EMPTY.LOG",
            "first_cluster": 0,
            "size": 0,
            "parent_id": 10,
        },
    ]

    parent_map = {10: "/Documents/Cases"}

    reconstructor = DeletedFileReconstructor(vdev, case_id="CASE-M11-FAT", evidence_id="ITEM-001")
    recovered = reconstructor.reconstruct_from_fat(
        deleted_entries=deleted_entries,
        allocated_clusters=allocated_clusters,
        sec_per_cluster=1,
        cluster_heap_start_lba=32,
        parent_paths=parent_map,
    )

    assert len(recovered) == 4

    # 1. Verify Intact Text File:
    rec_text = recovered[0]
    assert rec_text.original_name == "REPORT.TXT"
    assert rec_text.reconstructed_path == "/Documents/Cases/REPORT.TXT"
    assert rec_text.grade == RecoveryGrade.INTACT
    assert rec_text.sha256 == expected_text_hash  # Matches ground-truth hash!
    assert rec_text.validation_passed is True
    assert rec_text.validator_type == "TEXT"
    assert rec_text.provenance.source_lba == 32
    assert rec_text.provenance.overwritten_clusters == []

    # 2. Verify $OrphanFiles Fallback and PNG validation:
    rec_png = recovered[1]
    assert rec_png.original_name == "LOGO.PNG"
    assert rec_png.reconstructed_path == "/$OrphanFiles/LOGO.PNG"
    assert rec_png.grade == RecoveryGrade.INTACT
    assert rec_png.sha256 == expected_png_hash  # Matches ground-truth hash!
    assert rec_png.validation_passed is True
    assert rec_png.validator_type == "PNG"

    # 3. Verify Overwrite Detection & PARTIAL Grading:
    rec_doc = recovered[2]
    assert rec_doc.original_name == "DOC.BIN"
    assert rec_doc.grade == RecoveryGrade.PARTIAL  # Overwritten cluster 5 detected
    assert 5 in rec_doc.provenance.overwritten_clusters
    assert rec_doc.validation_passed is False  # Cannot claim success if not intact!

    # 4. Verify METADATA_ONLY Grading:
    rec_empty = recovered[3]
    assert rec_empty.grade == RecoveryGrade.METADATA_ONLY
    assert rec_empty.validation_passed is False

    # 5. Case Manifest Verification
    manifest = reconstructor.create_manifest(recovered)
    assert manifest.total_recovered == 4
    assert manifest.intact_count == 2
    assert manifest.partial_count == 1
    assert manifest.metadata_only_count == 1
    assert len(manifest.manifest_sha256) == 64

    # 6. Verify NO source modification occurred
    source_post_hash = hashlib.sha256(disk_path.read_bytes()).hexdigest()
    assert source_pre_hash == source_post_hash

    vdev.close()


# =========================================================================
# 2. NTFS DATA-RUN DECODING & RECONSTRUCTION TESTS
# =========================================================================


def test_ntfs_data_run_decoding() -> None:
    # Test vector:
    # Run 1: 0x21 0x14 0x00 0x01 -> length 20 (0x14), delta +256 (0x0100) -> LCN 256
    # Run 2: 0x21 0x10 0x20 0x01 -> length 16 (0x10), delta +288 (0x0120) -> LCN 544
    # Run 3: 0x00 -> terminator
    runlist = bytes([0x21, 0x14, 0x00, 0x01, 0x21, 0x10, 0x20, 0x01, 0x00])
    runs = decode_ntfs_data_runs(runlist)

    assert len(runs) == 2
    assert runs[0] == (256, 20)
    assert runs[1] == (544, 16)


def test_ntfs_reconstruction_and_manifest(tmp_path: Path) -> None:
    disk_path = tmp_path / "ntfs_recovery.img"
    create_blank_disk(disk_path, sector_count=2048)

    ground_truth_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
    pdf_hash = hashlib.sha256(ground_truth_pdf).hexdigest()

    # Write PDF payload at cluster 10 (LBA 80 @ 8 sec/cluster)
    with open(disk_path, "r+b") as f:
        f.seek(80 * 512)
        f.write(ground_truth_pdf)

    vdev = VirtualDevice(disk_path)

    # Build a runlist pointing to LCN 10 (length 1 cluster): 0x11 0x01 0x0A 0x00
    runlist = bytes([0x11, 0x01, 0x0A, 0x00])

    deleted_records = [
        {
            "name": "CASE_EVIDENCE.PDF",
            "parent_frn": 5,
            "filesize": len(ground_truth_pdf),
            "runlist_bytes": runlist,
            "mft_index": 42,
        },
        {
            "name": "ORPHANED_DATA.TXT",
            "parent_frn": 99999,  # Unresolvable parent -> $OrphanFiles
            "filesize": 14,
            "resident_data": b"RESIDENT DATA\n",
            "mft_index": 43,
        },
    ]

    reconstructor = DeletedFileReconstructor(vdev, case_id="CASE-NTFS-01", evidence_id="ITEM-42")
    recovered = reconstructor.reconstruct_from_ntfs_mft(
        deleted_records=deleted_records,
        allocated_clusters=set(),  # All clusters free
        sec_per_cluster=8,
        parent_paths={5: "/Root/Cases"},
    )

    assert len(recovered) == 2

    # 1. Non-resident PDF check
    rec_pdf = recovered[0]
    assert rec_pdf.reconstructed_path == "/Root/Cases/CASE_EVIDENCE.PDF"
    assert rec_pdf.grade == RecoveryGrade.INTACT
    assert rec_pdf.sha256 == pdf_hash
    assert rec_pdf.validation_passed is True
    assert rec_pdf.validator_type == "PDF"
    assert rec_pdf.provenance.source_lba == 80

    # 2. Resident text check with orphan fallback
    rec_txt = recovered[1]
    assert rec_txt.reconstructed_path == "/$OrphanFiles/ORPHANED_DATA.TXT"
    assert rec_txt.grade == RecoveryGrade.INTACT
    assert rec_txt.data == b"RESIDENT DATA\n"
    assert rec_txt.validation_passed is True

    # 3. Export Manifest to file
    manifest_path = str(tmp_path / "manifest.json")
    manifest = reconstructor.create_manifest(recovered)
    manifest.save_to_file(manifest_path)
    assert Path(manifest_path).exists()
    assert Path(manifest_path).stat().st_size > 0

    vdev.close()
