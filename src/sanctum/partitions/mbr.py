import struct
import logging
from typing import List, Tuple
from sanctum.dal import BaseDevice
from sanctum.partitions.models import PartitionEntry, PartitionScheme

logger = logging.getLogger("sanctum.partitions.mbr")

MBR_BOOT_SIGNATURE = b"\x55\xaa"
EXTENDED_PARTITION_TYPES = {0x05, 0x0F}

KNOWN_MBR_TYPES = {
    0x01: "FAT12",
    0x04: "FAT16 (<32MB)",
    0x06: "FAT16",
    0x07: "NTFS/exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x05: "Extended (CHS)",
    0x0F: "Extended (LBA)",
    0x82: "Linux Swap",
    0x83: "Linux Native (ext2/3/4)",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}


def parse_mbr_entry(raw_entry: bytes, index: int, sector_size: int = 512) -> Tuple[bool, Optional[PartitionEntry]]:
    """Parses a 16-byte MBR partition entry."""
    if len(raw_entry) != 16:
        return False, None

    boot_flag, start_chs, part_type, end_chs, start_lba, sector_count = struct.unpack(
        "<B3sB3sII", raw_entry
    )

    if part_type == 0x00 and sector_count == 0:
        # Unused entry
        return True, None

    is_bootable = (boot_flag == 0x80)
    is_extended = part_type in EXTENDED_PARTITION_TYPES
    fs_name = KNOWN_MBR_TYPES.get(part_type, f"Unknown (0x{part_type:02X})")
    end_lba = start_lba + sector_count - 1 if sector_count > 0 else start_lba

    entry = PartitionEntry(
        index=index,
        name=f"MBR Partition {index}",
        type_id=f"0x{part_type:02X}",
        start_lba=start_lba,
        end_lba=end_lba,
        sector_count=sector_count,
        size_bytes=sector_count * sector_size,
        bootable=is_bootable,
        is_extended=is_extended,
        is_logical=False,
        fs_type=fs_name,
        is_valid=(sector_count > 0 and start_lba >= 0),
    )
    return True, entry


def parse_mbr(device: BaseDevice) -> Tuple[bool, List[PartitionEntry], List[str]]:
    """
    Parses Master Boot Record at LBA 0 and follows extended partition EBR chains.
    Returns: (is_mbr, partitions, notes)
    """
    partitions: List[PartitionEntry] = []
    notes: List[str] = []

    try:
        mbr_sector = device.read_sector(0)
    except Exception as e:
        return False, [], [f"Failed to read LBA 0: {e}"]

    if len(mbr_sector) < 512:
        return False, [], ["LBA 0 is under 512 bytes."]

    if mbr_sector[510:512] != MBR_BOOT_SIGNATURE:
        return False, [], ["Invalid MBR boot signature (missing 0x55AA)."]

    sector_size = device.info.sector_size
    extended_roots: List[PartitionEntry] = []

    # Parse 4 primary entries
    for i in range(4):
        offset = 446 + (i * 16)
        raw_entry = mbr_sector[offset : offset + 16]
        valid, entry = parse_mbr_entry(raw_entry, index=i + 1, sector_size=sector_size)
        if valid and entry:
            # Check for GPT Protective MBR (0xEE)
            if entry.type_id == "0xEE":
                notes.append("GPT Protective MBR detected at LBA 0.")
                return False, [], notes

            partitions.append(entry)
            if entry.is_extended:
                extended_roots.append(entry)

    # Follow Extended Boot Record (EBR) chains for each extended partition
    logical_idx = 5
    for ext_root in extended_roots:
        current_ebr_lba = ext_root.start_lba
        max_hops = 64
        hops = 0

        while current_ebr_lba > 0 and hops < max_hops:
            hops += 1
            try:
                ebr_data = device.read_sector(current_ebr_lba)
            except Exception as e:
                notes.append(f"Failed to read EBR at LBA {current_ebr_lba}: {e}")
                break

            if ebr_data[510:512] != MBR_BOOT_SIGNATURE:
                notes.append(f"Invalid EBR signature at LBA {current_ebr_lba}.")
                break

            # Entry 1: Logical partition
            ebr_entry_1 = ebr_data[446 : 446 + 16]
            boot_flag, _, p_type, _, rel_start, count = struct.unpack(
                "<B3sB3sII", ebr_entry_1
            )

            if p_type != 0x00 and count > 0:
                abs_start = current_ebr_lba + rel_start
                abs_end = abs_start + count - 1
                fs_name = KNOWN_MBR_TYPES.get(p_type, f"Unknown (0x{p_type:02X})")

                partitions.append(
                    PartitionEntry(
                        index=logical_idx,
                        name=f"Logical Partition {logical_idx}",
                        type_id=f"0x{p_type:02X}",
                        start_lba=abs_start,
                        end_lba=abs_end,
                        sector_count=count,
                        size_bytes=count * sector_size,
                        bootable=(boot_flag == 0x80),
                        is_extended=False,
                        is_logical=True,
                        fs_type=fs_name,
                        is_valid=True,
                        notes=[f"EBR at LBA {current_ebr_lba}"],
                    )
                )
                logical_idx += 1

            # Entry 2: Next EBR link (relative to ext_root.start_lba)
            ebr_entry_2 = ebr_data[462 : 462 + 16]
            _, _, next_type, _, next_rel_start, _ = struct.unpack(
                "<B3sB3sII", ebr_entry_2
            )

            if next_type in EXTENDED_PARTITION_TYPES and next_rel_start > 0:
                current_ebr_lba = ext_root.start_lba + next_rel_start
            else:
                break

    return True, partitions, notes
