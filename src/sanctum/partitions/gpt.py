import zlib
import struct
import uuid
import logging
from typing import List, Tuple, Optional
from sanctum.dal import BaseDevice
from sanctum.partitions.models import PartitionEntry

logger = logging.getLogger("sanctum.partitions.gpt")

GPT_SIGNATURE = b"EFI PART"

KNOWN_GPT_GUIDS = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System Partition",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data (NTFS/FAT/exFAT)",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux Filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux Swap",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
}


def _format_guid(raw_16: bytes) -> str:
    """Formats GUID from mixed-endian byte array to standard UUID string."""
    if len(raw_16) != 16 or raw_16 == b"\x00" * 16:
        return ""
    # GPT GUIDs are stored in mixed-endian: Data1(LE), Data2(LE), Data3(LE), Data4(BE)
    d1, d2, d3, d4_0, d4_1 = struct.unpack("<IHHBB", raw_16[:10])
    d4_tail = raw_16[10:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4_0:02x}{d4_1:02x}-{d4_tail.hex()}"


def parse_gpt_header(header_data: bytes) -> Optional[dict]:
    """Parses a 92+ byte GPT header structure."""
    if len(header_data) < 92 or header_data[:8] != GPT_SIGNATURE:
        return None

    (
        sig,
        rev,
        hdr_size,
        hdr_crc,
        reserved,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid_raw,
        entries_lba,
        num_entries,
        entry_size,
        entries_crc,
    ) = struct.unpack("<8sIIIIQQQQ16sQIII", header_data[:92])

    return {
        "revision": rev,
        "header_size": hdr_size,
        "header_crc": hdr_crc,
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "first_usable_lba": first_usable_lba,
        "last_usable_lba": last_usable_lba,
        "disk_guid": _format_guid(disk_guid_raw),
        "entries_lba": entries_lba,
        "num_entries": num_entries,
        "entry_size": entry_size,
        "entries_crc": entries_crc,
    }


def validate_gpt_header_crc(header_data: bytes, header_info: dict) -> bool:
    """Verifies CRC32 of GPT header (with CRC field zeroed)."""
    hdr_size = header_info["header_size"]
    if len(header_data) < hdr_size:
        return False

    # Zero out bytes 16..20 (the CRC32 field)
    copy_hdr = bytearray(header_data[:hdr_size])
    copy_hdr[16:20] = b"\x00\x00\x00\x00"

    calc_crc = zlib.crc32(copy_hdr) & 0xFFFFFFFF
    return calc_crc == (header_info["header_crc"] & 0xFFFFFFFF)


def read_partition_entries(
    device: BaseDevice, entries_lba: int, num_entries: int, entry_size: int
) -> Tuple[bytes, List[PartitionEntry]]:
    """Reads partition array bytes and extracts valid entries."""
    sector_size = device.info.sector_size
    total_bytes = num_entries * entry_size
    sectors_to_read = (total_bytes + sector_size - 1) // sector_size

    raw_array = bytearray()
    for s in range(sectors_to_read):
        try:
            raw_array.extend(device.read_sector(entries_lba + s))
        except Exception:
            raw_array.extend(b"\x00" * sector_size)

    array_bytes = bytes(raw_array[:total_bytes])
    partitions: List[PartitionEntry] = []

    for i in range(num_entries):
        entry_raw = array_bytes[i * entry_size : (i + 1) * entry_size]
        if len(entry_raw) < 128:
            break

        type_guid_raw = entry_raw[:16]
        if type_guid_raw == b"\x00" * 16:
            continue  # Unused entry

        type_guid = _format_guid(type_guid_raw)
        part_guid = _format_guid(entry_raw[16:32])
        start_lba, end_lba, attributes = struct.unpack("<QQQ", entry_raw[32:56])
        name_raw = entry_raw[56:128]
        try:
            name = name_raw.decode("utf-16le").rstrip("\x00")
        except Exception:
            name = f"GPT Partition {i + 1}"

        if not name.strip():
            name = f"GPT Partition {i + 1}"

        count = (end_lba - start_lba + 1) if end_lba >= start_lba else 0
        fs_type = KNOWN_GPT_GUIDS.get(type_guid.lower(), "Unknown GPT Type")

        partitions.append(
            PartitionEntry(
                index=i + 1,
                name=name,
                type_id=type_guid,
                start_lba=start_lba,
                end_lba=end_lba,
                sector_count=count,
                size_bytes=count * sector_size,
                bootable=False,
                is_extended=False,
                is_logical=False,
                fs_type=fs_type,
                is_valid=(count > 0 and start_lba >= 0),
                notes=[f"Partition GUID: {part_guid}"],
            )
        )

    return array_bytes, partitions


def parse_gpt(
    device: BaseDevice,
) -> Tuple[bool, List[PartitionEntry], List[str], bool, List[str]]:
    """
    Parses GPT partition table with CRC32 checks and Backup GPT recovery.
    Returns: (is_gpt, partitions, notes, used_backup, repair_notes)
    """
    notes: List[str] = []
    repair_notes: List[str] = []
    used_backup = False

    # 1. Attempt Primary GPT Header at LBA 1
    primary_hdr_data = None
    try:
        primary_hdr_data = device.read_sector(1)
    except Exception as e:
        notes.append(f"Failed to read primary GPT header at LBA 1: {e}")

    primary_info = parse_gpt_header(primary_hdr_data) if primary_hdr_data else None
    primary_valid = False

    if primary_info:
        if validate_gpt_header_crc(primary_hdr_data, primary_info):
            # Check partition array CRC
            arr_bytes, partitions = read_partition_entries(
                device,
                primary_info["entries_lba"],
                primary_info["num_entries"],
                primary_info["entry_size"],
            )
            calc_arr_crc = zlib.crc32(arr_bytes) & 0xFFFFFFFF
            if calc_arr_crc == (primary_info["entries_crc"] & 0xFFFFFFFF):
                primary_valid = True
                notes.append("Primary GPT Header and Partition Array CRC32 verified successfully.")
                return True, partitions, notes, False, []
            else:
                notes.append("Primary GPT Partition Array CRC32 mismatch! Possible data corruption.")
        else:
            notes.append("Primary GPT Header CRC32 checksum mismatch!")
    else:
        notes.append("Primary GPT Header missing or invalid signature.")

    # 2. Backup GPT Recovery
    # Check backup GPT at last LBA
    total_lbas = device.info.lba_count
    backup_lba = total_lbas - 1
    notes.append(f"Attempting Backup GPT recovery at LBA {backup_lba}...")

    backup_hdr_data = None
    try:
        backup_hdr_data = device.read_sector(backup_lba)
    except Exception as e:
        notes.append(f"Failed to read backup GPT at LBA {backup_lba}: {e}")

    backup_info = parse_gpt_header(backup_hdr_data) if backup_hdr_data else None

    if backup_info and validate_gpt_header_crc(backup_hdr_data, backup_info):
        arr_bytes, partitions = read_partition_entries(
            device,
            backup_info["entries_lba"],
            backup_info["num_entries"],
            backup_info["entry_size"],
        )
        calc_arr_crc = zlib.crc32(arr_bytes) & 0xFFFFFFFF
        if calc_arr_crc == (backup_info["entries_crc"] & 0xFFFFFFFF):
            used_backup = True
            repair_notes.append("RECOVERED: Partition table recovered from valid Backup GPT.")
            notes.append("Backup GPT Header and Partition Array successfully validated.")
            return True, partitions, notes, True, repair_notes
        else:
            notes.append("Backup GPT Partition Array CRC32 mismatch.")
    else:
        notes.append("Backup GPT Header is also missing or corrupt.")

    return False, [], notes, False, repair_notes
