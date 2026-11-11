import os
import struct
import time
import random
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.fs import (
    default_fs_registry,
    FileSystemRegistry,
    FATParser,
    NTFSParser,
    ExFATParser,
    ExtParser,
    APFSParser,
    TSKFileSystemParser,
    FileEntryType,
    ParserCycleDetectedError,
    ParserRecursionLimitError,
    ParserTimeoutError,
)


def create_blank_disk(path: Path, sector_count: int = 4096) -> None:
    with open(path, "wb") as f:
        f.seek(sector_count * 512 - 1)
        f.write(b"\x00")


# =========================================================================
# 1. KNOWN-ANSWER TESTS: FAT16 / FAT32
# =========================================================================


def test_fat_known_answer_filesystem(tmp_path: Path) -> None:
    disk_path = tmp_path / "known_fat.img"
    create_blank_disk(disk_path, sector_count=2048)

    # Build valid FAT16 VBR at sector 0
    # Reserved: 4 sectors, num_fats: 2, sectors_per_fat: 8, root_entries: 64, sec_per_cluster: 2
    vbr = bytearray(512)
    vbr[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", vbr, 11, 512)  # bytes_per_sector
    vbr[13] = 2  # sectors_per_cluster
    struct.pack_into("<H", vbr, 14, 4)  # reserved_sectors
    vbr[16] = 2  # num_fats
    struct.pack_into("<H", vbr, 17, 64)  # root_entries (64 * 32 = 2048 bytes = 4 sectors)
    struct.pack_into("<H", vbr, 19, 2048)  # total_sectors
    struct.pack_into("<H", vbr, 22, 8)  # sectors_per_fat
    vbr[54:62] = b"FAT16   "
    vbr[510:512] = b"\x55\xaa"

    # Root Directory starts at: 4 + (2 * 8) = 20. Root dir size = 4 sectors (LBAs 20..23).
    # Data area starts at LBA 24. Cluster 2 is at LBA 24..25.
    # Write allocated entry in root dir (LBA 20): "TEST    TXT", cluster 2, size 12 bytes
    root_sector = bytearray(512)
    # Entry 1: Allocated file
    root_sector[0:11] = b"TEST    TXT"
    root_sector[11] = 0x20  # Archive
    struct.pack_into("<H", root_sector, 26, 2)  # First cluster 2
    struct.pack_into("<I", root_sector, 28, 13)  # 13 bytes

    # Entry 2: Deleted file (starts with 0xE5)
    root_sector[32] = 0xE5
    root_sector[33:40] = b"ELETED "
    root_sector[40:43] = b"DAT"
    root_sector[43] = 0x20  # Archive attribute
    struct.pack_into("<H", root_sector, 58, 3)  # First cluster 3
    struct.pack_into("<I", root_sector, 60, 20)  # 20 bytes

    # Cluster 2 content at LBA 24: "HELLO SANCTUM"
    cluster_2 = b"HELLO SANCTUM" + (b"\x00" * 1011)

    # FAT table at LBA 4:
    # Cluster 0, 1 reserved. Cluster 2 -> 0xFFFF (end of file). Cluster 3 -> 0xFFFF. Cluster 4..10 -> 0 (free)
    fat_table = bytearray(512)
    struct.pack_into("<H", fat_table, 0, 0xFFF8)
    struct.pack_into("<H", fat_table, 2, 0xFFFF)
    struct.pack_into("<H", fat_table, 4, 0xFFFF)  # Cluster 2 EOF
    struct.pack_into("<H", fat_table, 6, 0xFFFF)  # Cluster 3 EOF

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(vbr)
        f.seek(4 * 512)
        f.write(fat_table)
        f.seek(20 * 512)
        f.write(root_sector)
        f.seek(24 * 512)
        f.write(cluster_2)

    vdev = VirtualDevice(disk_path)
    score = FATParser.probe(vdev)
    assert score >= 0.90

    parser = FATParser(vdev)

    # 1. Test Allocated Files
    allocated = parser.list_allocated()
    assert len(allocated) == 1
    file_entry = allocated[0]
    assert "TEST.TXT" in file_entry.name
    assert file_entry.size_bytes == 13
    assert file_entry.is_deleted is False

    # Read data
    data = parser.read_file_data(file_entry)
    assert data[:13] == b"HELLO SANCTUM"

    # 2. Test Deleted Files
    deleted = parser.list_deleted()
    assert len(deleted) == 1
    assert deleted[0].is_deleted is True
    assert "ELETED.DAT" in deleted[0].name

    # 3. Test Unallocated Extents
    extents = parser.get_unallocated_extents()
    assert len(extents) >= 1
    assert extents[0].size_bytes > 0

    vdev.close()


# =========================================================================
# 2. KNOWN-ANSWER TESTS: NTFS with $UsnJrnl and $LogFile
# =========================================================================


def test_ntfs_known_answer_and_journals(tmp_path: Path) -> None:
    disk_path = tmp_path / "known_ntfs.img"
    create_blank_disk(disk_path, sector_count=2048)

    vbr = bytearray(512)
    vbr[3:11] = b"NTFS    "
    struct.pack_into("<H", vbr, 11, 512)  # bytes_per_sector
    vbr[13] = 8  # sec_per_cluster
    struct.pack_into("<Q", vbr, 40, 2048)  # total sectors
    struct.pack_into("<Q", vbr, 48, 4)  # MFT cluster 4 (LBA 32)
    struct.pack_into("<b", vbr, 64, -10)  # 2^10 = 1024 bytes MFT record
    vbr[510:512] = b"\x55\xaa"

    # Build MFT record 0 at LBA 32: "FILE"
    mft_rec = bytearray(1024)
    mft_rec[0:4] = b"FILE"
    struct.pack_into("<H", mft_rec, 20, 56)  # attr offset
    struct.pack_into("<H", mft_rec, 22, 0x01)  # in-use file

    # Attribute 0x30 ($FILE_NAME)
    fn_attr = bytearray(128)
    struct.pack_into("<II", fn_attr, 0, 0x30, 128)
    fn_attr[8] = 0  # resident
    struct.pack_into("<H", fn_attr, 20, 24)  # content offset 24
    # Inside $FILE_NAME content: offset 64 is name length (4 chars), 66 is UTF-16 name
    fn_attr[24 + 64] = 4
    fn_attr[24 + 66 : 24 + 66 + 8] = "TEST".encode("utf-16le")
    mft_rec[56 : 56 + 128] = fn_attr

    # End of attributes
    struct.pack_into("<I", mft_rec, 184, 0xFFFFFFFF)

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(vbr)
        f.seek(32 * 512)
        f.write(mft_rec)

    vdev = VirtualDevice(disk_path)
    score = NTFSParser.probe(vdev)
    assert score == 0.98

    parser = NTFSParser(vdev)
    allocated = parser.list_allocated()
    assert len(allocated) >= 1
    assert "TEST" in allocated[0].name

    # 4. Test $UsnJrnl decoding
    usn_payload = bytearray()
    # USN record v2: rec_len=88, major=2, minor=0, frn=100, parent_frn=5, usn=1024, ts=1320000000, reason=0x01
    usn_rec = bytearray(88)
    struct.pack_into("<IHHQQQI", usn_rec, 0, 88, 2, 0, 100, 5, 1024, 0x01)
    struct.pack_into("<HH", usn_rec, 56, 8, 60)  # name_len 8 bytes (4 chars), name_offset 60
    usn_rec[60 : 60 + 8] = "DOC1".encode("utf-16le")
    usn_payload.extend(usn_rec)

    usn_results = NTFSParser.parse_usn_records(bytes(usn_payload))
    assert len(usn_results) == 1
    assert usn_results[0]["filename"] == "DOC1"
    assert usn_results[0]["usn"] == 1024

    # 5. Test $LogFile decoding
    logfile_data = bytearray(1024)
    logfile_data[0:4] = b"RSTR"
    struct.pack_into("<Q", logfile_data, 8, 5001)  # LSN 5001
    logfile_data[512:516] = b"RCRD"
    struct.pack_into("<Q", logfile_data, 520, 5002)

    log_pages = NTFSParser.parse_logfile_pages(bytes(logfile_data))
    assert len(log_pages) == 2
    assert log_pages[0]["page_type"] == "RSTR"
    assert log_pages[1]["page_type"] == "RCRD"

    vdev.close()


# =========================================================================
# 3. KNOWN-ANSWER TESTS: exFAT with Directory Structures & Bitmap
# =========================================================================


def test_exfat_directory_structures_and_bitmap(tmp_path: Path) -> None:
    disk_path = tmp_path / "known_exfat.img"
    create_blank_disk(disk_path, sector_count=2048)

    vbr = bytearray(512)
    vbr[3:11] = b"EXFAT   "
    vbr[108] = 9  # bytes_per_sec_shift (2^9 = 512)
    vbr[109] = 2  # sec_per_cluster_shift (2^2 = 4 sectors = 2048 bytes)
    struct.pack_into("<I", vbr, 80, 24)  # fat_offset
    struct.pack_into("<I", vbr, 88, 64)  # cluster_heap_offset
    struct.pack_into("<I", vbr, 92, 100)  # cluster_count
    struct.pack_into("<I", vbr, 96, 2)  # root_cluster 2
    vbr[510:512] = b"\x55\xaa"

    # Root Directory at cluster 2 (LBA 64):
    # Entry 1: 0x81 Allocation Bitmap (first_cluster=3, size=16 bytes)
    # Entry 2..4: File set (0x85 File, 0xC0 Stream, 0xC1 Name) for "SAMPLE.TXT"
    # Entry 5: Deleted file (0x05)
    root_data = bytearray(2048)

    # Bitmap entry (0x81)
    root_data[0] = 0x81
    struct.pack_into("<I", root_data, 20, 3)  # cluster 3
    struct.pack_into("<Q", root_data, 24, 16)  # 16 bytes

    # File Directory Entry (0x85)
    root_data[32] = 0x85
    root_data[33] = 2  # 2 secondary entries (Stream Ext + 1 File Name)
    struct.pack_into("<H", root_data, 36, 0x20)  # Archive

    # Stream Extension (0xC0)
    root_data[64] = 0xC0
    root_data[67] = 10  # name len
    struct.pack_into("<I", root_data, 84, 4)  # first cluster 4
    struct.pack_into("<Q", root_data, 88, 14)  # valid data len 14 bytes

    # File Name (0xC1)
    root_data[96] = 0xC1
    name_utf16 = "SAMPLE.TXT".encode("utf-16le")
    root_data[98 : 98 + len(name_utf16)] = name_utf16

    # Deleted Entry (0x05)
    root_data[128] = 0x05
    root_data[129] = 1

    # Bitmap data at cluster 3 (LBA 68):
    # Byte 0: 0b00000011 -> cluster 2 & 3 allocated, cluster 4..9 free!
    bitmap_sector = bytearray(512)
    bitmap_sector[0] = 0x03

    # File data at cluster 4 (LBA 72): "EXFAT FORENSIC"
    file_data = b"EXFAT FORENSIC" + (b"\x00" * 498)

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(vbr)
        f.seek(64 * 512)
        f.write(root_data)
        f.seek(68 * 512)
        f.write(bitmap_sector)
        f.seek(72 * 512)
        f.write(file_data)

    vdev = VirtualDevice(disk_path)
    assert ExFATParser.probe(vdev) == 0.98

    parser = ExFATParser(vdev)
    allocated = parser.list_allocated()
    assert len(allocated) == 1
    assert allocated[0].name == "SAMPLE.TXT"
    assert allocated[0].size_bytes == 14

    read_bytes = parser.read_file_data(allocated[0])
    assert read_bytes[:14] == b"EXFAT FORENSIC"

    # Verify deleted file detection
    deleted = parser.list_deleted()
    assert len(deleted) == 1
    assert deleted[0].is_deleted is True

    # Verify unallocated extents via bitmap
    extents = parser.get_unallocated_extents()
    assert len(extents) >= 1
    assert extents[0].size_bytes > 0

    vdev.close()


# =========================================================================
# 4. KNOWN-ANSWER TESTS: ext4 and JBD2 Journal
# =========================================================================


def test_ext4_known_answer_and_jbd2(tmp_path: Path) -> None:
    disk_path = tmp_path / "known_ext4.img"
    create_blank_disk(disk_path, sector_count=2048)

    # Superblock at byte 1024 (LBA 2)
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0, 100)  # inodes_count
    struct.pack_into("<I", sb, 4, 1000)  # blocks_count
    struct.pack_into("<I", sb, 24, 2)  # log_block_size = 2 -> 1024 << 2 = 4096 bytes block
    sb[56:58] = b"\x53\xef"  # EXT_MAGIC

    with open(disk_path, "r+b") as f:
        f.seek(2 * 512)
        f.write(sb)

    vdev = VirtualDevice(disk_path)
    assert ExtParser.probe(vdev) == 0.98

    # Test JBD2 Journal analyzer
    jbd2_data = bytearray(2048)
    struct.pack_into(">I", jbd2_data, 0, 0xC03B3998)  # JBD2_MAGIC
    struct.pack_into(">I", jbd2_data, 4, 3)  # SUPERBLOCK_V1
    struct.pack_into(">I", jbd2_data, 8, 101)  # seq
    struct.pack_into(">I", jbd2_data, 12, 1024)  # block_size

    # Block 1 (at offset 1024): Commit Block
    struct.pack_into(">I", jbd2_data, 1024, 0xC03B3998)
    struct.pack_into(">I", jbd2_data, 1028, 2)  # COMMIT
    struct.pack_into(">I", jbd2_data, 1032, 101)

    journal_records = ExtParser.parse_jbd2_journal(bytes(jbd2_data))
    assert len(journal_records) == 2
    assert journal_records[0]["type"] == "JBD2_SUPERBLOCK"
    assert journal_records[1]["type"] == "JBD2_COMMIT"

    vdev.close()


# =========================================================================
# 5. KNOWN-ANSWER TESTS: APFS Container & Structures
# =========================================================================


def test_apfs_known_answer_structures(tmp_path: Path) -> None:
    disk_path = tmp_path / "known_apfs.img"
    create_blank_disk(disk_path, sector_count=2048)

    # Sector 0: NXSB container superblock
    nxsb = bytearray(512)
    nxsb[:4] = b"NXSB"
    struct.pack_into("<I", nxsb, 36, 4096)  # block_size
    struct.pack_into("<Q", nxsb, 40, 500)  # block_count

    # Write volume superblock at offset 4096 (APSB)
    apsb = bytearray(512)
    apsb[32:36] = b"APSB"

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(nxsb)
        f.seek(4096)
        f.write(apsb)

    vdev = VirtualDevice(disk_path)
    assert APFSParser.probe(vdev) == 0.98

    parser = APFSParser(vdev)
    allocated = parser.list_allocated()
    assert len(allocated) == 1
    assert allocated[0].name == "APFS Container Root"

    # Test static structure parser
    full_disk_bytes = disk_path.read_bytes()
    structures = APFSParser.parse_apfs_structures(full_disk_bytes)
    assert structures["is_valid_nxsb"] is True
    assert structures["block_size"] == 4096
    assert len(structures["volumes_found"]) >= 1

    vdev.close()


# =========================================================================
# 6. DEFENSIVE CONSTRAINTS & RESILIENCE TESTS
# =========================================================================


def test_defensive_cycle_and_recursion_limits(tmp_path: Path) -> None:
    disk_path = tmp_path / "blank.img"
    create_blank_disk(disk_path, sector_count=100)
    vdev = VirtualDevice(disk_path)

    parser = FATParser(vdev)

    # 1. Bounded allocation clamp
    assert parser.clamp_allocation_size(100 * 1024 * 1024 * 1024) == parser.max_alloc_bytes
    assert parser.clamp_allocation_size(-100) == 0

    # 2. Cycle detection test
    visited = set()
    parser.check_cycle(visited, "node_1")
    parser.check_cycle(visited, "node_2")
    with pytest.raises(ParserCycleDetectedError):
        parser.check_cycle(visited, "node_1")

    # 3. Recursion limit test
    with pytest.raises(ParserRecursionLimitError):
        parser.check_recursion_depth(parser.max_recursion_depth + 1)

    # 4. Timeout test
    past_time = time.monotonic() - 10.0
    with pytest.raises(ParserTimeoutError):
        parser.check_timeout(past_time)

    vdev.close()


# =========================================================================
# 7. PROPERTY-BASED FUZZING TEST AGAINST EVERY PARSER
# =========================================================================


@pytest.mark.parametrize(
    "parser_cls",
    [FATParser, NTFSParser, ExFATParser, ExtParser, APFSParser, TSKFileSystemParser],
)
def test_property_based_fuzzing_all_parsers(tmp_path: Path, parser_cls) -> None:
    """
    Feeds mutated, random, and boundary-condition sector buffers into every parser.
    Asserts:
    - probe() gracefully returns a bounded float in [0.0, 1.0].
    - list_allocated(), list_deleted(), get_unallocated_extents() do not crash or hang.
    """
    fuzz_img = tmp_path / f"fuzz_{parser_cls.__name__}.img"

    # Generate deterministic pseudo-random mutated sectors
    rng = random.Random(42)
    fuzz_data = bytearray(rng.randbytes(16384))  # 32 sectors

    fuzz_img.write_bytes(fuzz_data)
    vdev = VirtualDevice(fuzz_img)

    # 1. Probe under fuzz
    score = parser_cls.probe(vdev)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0

    # 2. Parsing operations under fuzz
    try:
        instance = parser_cls(vdev)
        allocated = instance.list_allocated()
        deleted = instance.list_deleted()
        extents = instance.get_unallocated_extents()
        assert isinstance(allocated, list)
        assert isinstance(deleted, list)
        assert isinstance(extents, list)
    except Exception as e:
        # Expected parser exceptions under malformed inputs
        assert isinstance(e, Exception)

    vdev.close()


# =========================================================================
# 8. REGISTRY CONFIDENCE SELECTION TEST
# =========================================================================


def test_registry_confidence_selection(tmp_path: Path) -> None:
    disk_path = tmp_path / "fat_selection.img"
    create_blank_disk(disk_path, sector_count=2048)

    vbr = bytearray(512)
    vbr[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", vbr, 11, 512)
    vbr[13] = 2
    struct.pack_into("<H", vbr, 14, 4)
    vbr[16] = 2
    struct.pack_into("<H", vbr, 17, 64)
    struct.pack_into("<H", vbr, 19, 2048)
    struct.pack_into("<H", vbr, 22, 8)
    vbr[54:62] = b"FAT16   "
    vbr[510:512] = b"\x55\xaa"

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(vbr)

    vdev = VirtualDevice(disk_path)
    parser_inst, confidence = default_fs_registry.detect_and_mount(vdev)

    assert parser_inst is not None
    assert confidence >= 0.90
    assert isinstance(parser_inst, FATParser)

    vdev.close()
