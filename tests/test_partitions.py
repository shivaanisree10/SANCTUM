import os
import struct
import zlib
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.dal.device import DeviceWriteError, DeviceReadError
from sanctum.partitions import (
    PartitionMapper,
    PartitionScheme,
    VirtualVolume,
    detect_filesystem_at_lba,
)


def create_blank_disk(path: Path, sector_count: int = 8192) -> None:
    """Initializes a blank disk image."""
    with open(path, "wb") as f:
        f.seek(sector_count * 512 - 1)
        f.write(b"\x00")


def write_mbr_sector(
    path: Path,
    entries: list[tuple[int, int, int, bool]],
    valid_sig: bool = True,
) -> None:
    """
    Writes MBR sector at LBA 0.
    entries: list of (part_type, start_lba, sector_count, is_bootable)
    """
    sector = bytearray(512)
    for i, (p_type, start_lba, count, boot) in enumerate(entries[:4]):
        boot_byte = 0x80 if boot else 0x00
        packed = struct.pack(
            "<B3sB3sII",
            boot_byte,
            b"\x00\x00\x00",
            p_type,
            b"\x00\x00\x00",
            start_lba,
            count,
        )
        offset = 446 + (i * 16)
        sector[offset : offset + 16] = packed

    if valid_sig:
        sector[510:512] = b"\x55\xaa"
    else:
        sector[510:512] = b"\x00\x00"

    with open(path, "r+b") as f:
        f.seek(0)
        f.write(sector)


def build_gpt_disk_image(
    path: Path,
    part_specs: list[tuple[str, int, int, str]],
    total_lbas: int = 8192,
    corrupt_primary_header: bool = False,
    corrupt_backup_header: bool = False,
) -> None:
    """
    Builds a standards-compliant GPT disk image with primary and backup tables.
    part_specs: list of (type_guid, start_lba, end_lba, name)
    """
    create_blank_disk(path, sector_count=total_lbas)

    # 1. Protective MBR at LBA 0
    write_mbr_sector(path, [(0xEE, 1, total_lbas - 1, False)])

    # 2. Build 128 partition entries (16384 bytes = 32 sectors)
    entry_size = 128
    num_entries = 128
    entries_bytes = bytearray(num_entries * entry_size)

    for i, (type_guid_str, s_lba, e_lba, name) in enumerate(part_specs):
        # Convert standard UUID to mixed-endian 16 bytes
        type_guid_bytes = bytearray(16)
        # Simplified deterministic type GUID for test
        type_guid_bytes[:8] = b"TESTGUID"
        part_guid_bytes = bytearray(16)
        part_guid_bytes[:8] = f"PART{i:04d}".encode("ascii")

        name_utf16 = name.encode("utf-16le")[:72]
        name_field = name_utf16.ljust(72, b"\x00")

        entry_data = struct.pack(
            "<16s16sQQQ72s",
            bytes(type_guid_bytes),
            bytes(part_guid_bytes),
            s_lba,
            e_lba,
            0,  # attributes
            name_field,
        )
        entries_bytes[i * entry_size : (i + 1) * entry_size] = entry_data

    entries_crc = zlib.crc32(entries_bytes) & 0xFFFFFFFF

    # 3. Primary GPT Header at LBA 1
    # header_size = 92
    primary_hdr = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0,  # placeholder CRC
        0,
        1,  # current LBA
        total_lbas - 1,  # backup LBA
        34,  # first usable
        total_lbas - 34,  # last usable
        b"DISK-GUID-123456",
        2,  # entries LBA
        num_entries,
        entry_size,
        entries_crc,
    )
    # Calculate Primary Header CRC32
    prim_crc = zlib.crc32(primary_hdr[:92]) & 0xFFFFFFFF
    primary_hdr = bytearray(primary_hdr)
    primary_hdr[16:20] = struct.pack("<I", prim_crc)
    primary_hdr = primary_hdr.ljust(512, b"\x00")

    if corrupt_primary_header:
        primary_hdr[16:20] = b"\xde\xad\xbe\xef"  # Invalid CRC

    # 4. Backup GPT Header at LBA (total_lbas - 1)
    backup_entries_lba = total_lbas - 33
    backup_hdr = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        92,
        0,  # placeholder CRC
        0,
        total_lbas - 1,  # current LBA (backup)
        1,  # backup LBA (points to primary)
        34,
        total_lbas - 34,
        b"DISK-GUID-123456",
        backup_entries_lba,
        num_entries,
        entry_size,
        entries_crc,
    )
    back_crc = zlib.crc32(backup_hdr[:92]) & 0xFFFFFFFF
    backup_hdr = bytearray(backup_hdr)
    backup_hdr[16:20] = struct.pack("<I", back_crc)
    backup_hdr = backup_hdr.ljust(512, b"\x00")

    if corrupt_backup_header:
        backup_hdr[0:8] = b"CORRUPT!"

    # Write to disk image
    with open(path, "r+b") as f:
        # Write Primary Header & Entries
        f.seek(1 * 512)
        f.write(primary_hdr)
        f.seek(2 * 512)
        f.write(entries_bytes)

        # Write Backup Entries & Header
        f.seek(backup_entries_lba * 512)
        f.write(entries_bytes)
        f.seek((total_lbas - 1) * 512)
        f.write(backup_hdr)


# =========================================================================
# TEST SUITE
# =========================================================================


def test_valid_mbr(tmp_path: Path) -> None:
    disk_path = tmp_path / "valid_mbr.img"
    create_blank_disk(disk_path, sector_count=4096)
    # Partition 1: NTFS, start 2048, count 1000
    # Partition 2: Linux, start 3100, count 500
    write_mbr_sector(disk_path, [(0x07, 2048, 1000, True), (0x83, 3100, 500, False)])

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    assert pmap.scheme == PartitionScheme.MBR
    assert len(pmap.partitions) == 2
    assert pmap.is_consistent is True

    p1 = pmap.partitions[0]
    assert p1.start_lba == 2048
    assert p1.sector_count == 1000
    assert p1.bootable is True
    assert "NTFS" in p1.fs_type

    p2 = pmap.partitions[1]
    assert p2.start_lba == 3100
    assert p2.sector_count == 500
    assert p2.bootable is False

    # Test VirtualVolume
    vols = mapper.get_volumes()
    assert len(vols) == 2
    v1 = vols[0]
    assert v1.info.lba_count == 1000
    assert v1.info.capacity_bytes == 1000 * 512
    # Verify write is strictly disabled
    with pytest.raises(DeviceWriteError):
        v1.write_sector(0, b"\x00" * 512)

    vdev.close()


def test_extended_mbr_ebr_chain(tmp_path: Path) -> None:
    disk_path = tmp_path / "ext_mbr.img"
    create_blank_disk(disk_path, sector_count=8192)

    # Primary 1: start 2048, count 1000
    # Extended 2: start 3100, count 3000 (type 0x05)
    write_mbr_sector(disk_path, [(0x07, 2048, 1000, False), (0x05, 3100, 3000, False)])

    # Write EBR 1 at LBA 3100:
    # Logical part 1: rel_start 1, count 500 (abs start 3101)
    # Next EBR: rel_start 1000 (abs start 4100)
    ebr1 = bytearray(512)
    ebr1[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x00\x00", 0x83, b"\x00\x00\x00", 1, 500)
    ebr1[462:478] = struct.pack("<B3sB3sII", 0, b"\x00\x00\x00", 0x05, b"\x00\x00\x00", 1000, 1000)
    ebr1[510:512] = b"\x55\xaa"

    # Write EBR 2 at LBA 4100:
    # Logical part 2: rel_start 1, count 800 (abs start 4101)
    # Next EBR: none (0)
    ebr2 = bytearray(512)
    ebr2[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x00\x00", 0x0B, b"\x00\x00\x00", 1, 800)
    ebr2[510:512] = b"\x55\xaa"

    with open(disk_path, "r+b") as f:
        f.seek(3100 * 512)
        f.write(ebr1)
        f.seek(4100 * 512)
        f.write(ebr2)

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    assert pmap.scheme == PartitionScheme.MBR
    # 1 primary + 1 extended container + 2 logicals = 4 partitions
    assert len(pmap.partitions) == 4
    logicals = [p for p in pmap.partitions if p.is_logical]
    assert len(logicals) == 2
    assert logicals[0].start_lba == 3101
    assert logicals[0].sector_count == 500
    assert logicals[1].start_lba == 4101
    assert logicals[1].sector_count == 800
    assert "FAT32" in logicals[1].fs_type

    vdev.close()


def test_damaged_mbr_fallback_signature_reconstruction(tmp_path: Path) -> None:
    disk_path = tmp_path / "damaged_mbr.img"
    create_blank_disk(disk_path, sector_count=8192)

    # Invalidate MBR signature (0x0000 instead of 0x55AA)
    write_mbr_sector(disk_path, [(0x07, 2048, 1000, False)], valid_sig=False)

    # Inject valid NTFS boot sector at 1 MiB alignment (LBA 2048)
    ntfs_boot = bytearray(512)
    ntfs_boot[3:11] = b"NTFS    "
    struct.pack_into("<Q", ntfs_boot, 40, 2000)  # 2000 sectors
    ntfs_boot[510:512] = b"\x55\xaa"

    with open(disk_path, "r+b") as f:
        f.seek(2048 * 512)
        f.write(ntfs_boot)

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    # Should detect damaged MBR and virtually reconstruct from NTFS signature
    assert pmap.scheme == PartitionScheme.INFERRED
    assert pmap.is_repaired is True
    assert len(pmap.partitions) >= 1
    inferred_p = pmap.partitions[0]
    assert inferred_p.start_lba == 2048
    assert inferred_p.fs_type == "NTFS"

    # Test repair script generation
    script_path = tmp_path / "repair.sh"
    mapper.generate_repair_script(str(script_path))
    assert script_path.exists()
    script_text = script_path.read_text(encoding="utf-8")
    assert "parted" in script_text
    assert "2048" in script_text

    vdev.close()


def test_valid_gpt(tmp_path: Path) -> None:
    disk_path = tmp_path / "valid_gpt.img"
    part_specs = [
        ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", 2048, 4095, "EFI System"),
        ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", 4096, 7000, "Windows Data"),
    ]
    build_gpt_disk_image(disk_path, part_specs, total_lbas=8192)

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    assert pmap.scheme == PartitionScheme.GPT
    assert len(pmap.partitions) == 2
    assert pmap.is_repaired is False
    assert pmap.is_consistent is True

    p1 = pmap.partitions[0]
    assert p1.name == "EFI System"
    assert p1.start_lba == 2048
    assert p1.end_lba == 4095

    p2 = pmap.partitions[1]
    assert p2.name == "Windows Data"
    assert p2.start_lba == 4096
    assert p2.end_lba == 7000

    vdev.close()


def test_damaged_primary_gpt_backup_recovery(tmp_path: Path) -> None:
    disk_path = tmp_path / "damaged_primary_gpt.img"
    part_specs = [
        ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", 2048, 5000, "Recovered Data"),
    ]
    # Corrupt Primary Header CRC, but keep Backup Header intact
    build_gpt_disk_image(
        disk_path,
        part_specs,
        total_lbas=8192,
        corrupt_primary_header=True,
        corrupt_backup_header=False,
    )

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    # Must fall back to Backup GPT and mark is_repaired == True
    assert pmap.scheme == PartitionScheme.GPT
    assert pmap.is_repaired is True
    assert len(pmap.partitions) == 1
    assert pmap.partitions[0].name == "Recovered Data"
    assert pmap.partitions[0].start_lba == 2048
    assert any("Backup GPT" in note for note in pmap.repair_notes)

    vdev.close()


def test_corrupted_partition_layouts_overlap_and_capacity(tmp_path: Path) -> None:
    disk_path = tmp_path / "corrupt_layout.img"
    create_blank_disk(disk_path, sector_count=4096)

    # Overlapping partitions and out-of-bounds capacity:
    # Partition 1: start 100, count 1000 (ends at 1099)
    # Partition 2: start 500, count 500 (ends at 999) -> OVERLAPS with P1!
    # Partition 3: start 3500, count 1000 (ends at 4499) -> EXCEEDS total 4096 capacity!
    write_mbr_sector(
        disk_path,
        [
            (0x07, 100, 1000, False),
            (0x83, 500, 500, False),
            (0x07, 3500, 1000, False),
        ],
    )

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    assert pmap.scheme == PartitionScheme.MBR
    assert pmap.is_consistent is False
    assert len(pmap.overlaps) > 0
    assert any("Overlapping partitions" in o for o in pmap.overlaps)
    assert len(pmap.capacity_violations) > 0
    assert any("exceeds disk boundary" in c for c in pmap.capacity_violations)

    vdev.close()
