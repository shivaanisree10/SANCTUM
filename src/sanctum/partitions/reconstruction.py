import struct
import logging
from typing import List, Optional, Tuple
from sanctum.dal import BaseDevice
from sanctum.partitions.models import PartitionEntry, PartitionScheme, PartitionMap

logger = logging.getLogger("sanctum.partitions.reconstruction")

COMMON_ALIGNMENTS = [
    63,      # Legacy DOS 63-sector alignment
    2048,    # 1 MiB standard alignment (2048 * 512B)
    4096,    # 2 MiB
    8192,    # 4 MiB
    264192,  # 129 MiB
    2097152, # 1 GiB
]


def detect_filesystem_at_lba(device: BaseDevice, lba: int) -> Optional[Tuple[str, int]]:
    """
    Inspects LBA for filesystem magic headers.
    Returns: (fs_type, inferred_sector_count) or None
    """
    try:
        sector_data = device.read_sector(lba)
    except Exception:
        return None

    if len(sector_data) < 512:
        return None

    # 1. NTFS: "NTFS    " at offset 3, boot signature at 510
    if sector_data[3:11] == b"NTFS    " and sector_data[510:512] == b"\x55\xaa":
        total_sectors = struct.unpack("<Q", sector_data[40:48])[0]
        return "NTFS", total_sectors

    # 2. exFAT: "EXFAT   " at offset 3, boot signature at 510
    if sector_data[3:11] == b"EXFAT   " and sector_data[510:512] == b"\x55\xaa":
        vol_length_sectors = struct.unpack("<Q", sector_data[72:80])[0]
        return "exFAT", vol_length_sectors

    # 3. FAT32: "FAT32   " at offset 82, boot signature at 510
    if len(sector_data) >= 90 and sector_data[82:90] == b"FAT32   " and sector_data[510:512] == b"\x55\xaa":
        total_sectors = struct.unpack("<I", sector_data[32:36])[0]
        return "FAT32", total_sectors

    # 4. FAT16: "FAT16   " at offset 54, boot signature at 510
    if len(sector_data) >= 62 and sector_data[54:62] == b"FAT16   " and sector_data[510:512] == b"\x55\xaa":
        total_sectors = struct.unpack("<H", sector_data[19:21])[0]
        if total_sectors == 0:
            total_sectors = struct.unpack("<I", sector_data[32:36])[0]
        return "FAT16", total_sectors

    # 5. ext2/3/4: Superblock is located at byte 1024 (LBA + 2 for 512B sectors)
    try:
        sb_sector = device.read_sector(lba + 2)
        if len(sb_sector) >= 60:
            magic = sb_sector[56:58]
            if magic == b"\x53\xef":
                blocks_count = struct.unpack("<I", sb_sector[4:8])[0]
                log_block_size = struct.unpack("<I", sb_sector[24:28])[0]
                block_size = 1024 << log_block_size
                sectors = (blocks_count * block_size) // device.info.sector_size
                return "ext4/ext3/ext2", sectors
    except Exception:
        pass

    # 6. Apple APFS Container Superblock: "NXSB" at offset 0
    if sector_data[:4] == b"NXSB":
        return "APFS", 0

    return None


def infer_partitions_from_signatures(
    device: BaseDevice, scan_limit_lbas: Optional[int] = None
) -> List[PartitionEntry]:
    """
    Scans common alignment boundaries (1 MiB, 2048-sector, 63-sector)
    for known filesystem signatures.
    """
    total_lbas = device.info.lba_count
    sector_size = device.info.sector_size
    limit = scan_limit_lbas or min(total_lbas, 200000)

    inferred: List[PartitionEntry] = []
    seen_starts = set()
    idx = 1

    # Candidates: common alignment points, plus 1 MiB steps (every 2048 sectors)
    candidate_lbas = set(COMMON_ALIGNMENTS)
    for step in range(2048, limit, 2048):
        candidate_lbas.add(step)

    for lba in sorted(candidate_lbas):
        if lba >= total_lbas or lba in seen_starts:
            continue

        result = detect_filesystem_at_lba(device, lba)
        if result:
            fs_name, sec_count = result
            if sec_count <= 0 or (lba + sec_count > total_lbas):
                # Fallback estimate to disk end or next alignment
                sec_count = total_lbas - lba

            end_lba = lba + sec_count - 1
            inferred.append(
                PartitionEntry(
                    index=idx,
                    name=f"Inferred {fs_name} Partition",
                    type_id="INFERRED",
                    start_lba=lba,
                    end_lba=end_lba,
                    sector_count=sec_count,
                    size_bytes=sec_count * sector_size,
                    bootable=False,
                    is_extended=False,
                    is_logical=False,
                    fs_type=fs_name,
                    is_valid=True,
                    notes=[f"Signature detected at LBA {lba} ({lba * sector_size // 1024} KB)"],
                )
            )
            seen_starts.add(lba)
            idx += 1

    return inferred


def virtually_reconstruct_partitions(device: BaseDevice) -> Tuple[List[PartitionEntry], List[str]]:
    """
    Reconstructs damaged partition table in-memory using heuristic signature inference.
    NEVER touches or writes to the underlying storage device.
    """
    repair_notes = ["Initiating virtual partition reconstruction from filesystem signatures."]
    inferred = infer_partitions_from_signatures(device)

    if inferred:
        repair_notes.append(
            f"VIRTUAL RECONSTRUCTION: Discovered {len(inferred)} valid partition(s) via alignment signature scan."
        )
    else:
        repair_notes.append("VIRTUAL RECONSTRUCTION: No known filesystem signatures discovered.")

    return inferred, repair_notes


def generate_repair_script(partition_map: PartitionMap, output_path: str) -> None:
    """
    Generates an external, non-destructive repair script (e.g. for sfdisk / parted).
    NEVER writes changes to the source evidence.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# ====================================================================",
        "# SANCTUM FORENSIC VIRTUAL REPAIR SCRIPT",
        "# Generated for partition recovery. Review carefully before execution.",
        "# WARNING: Never run this directly against evidence media!",
        "# Apply ONLY against exported forensic copies.",
        "# ====================================================================",
        "",
        'TARGET_IMAGE="${1:-evidence_copy.raw}"',
        'echo "Applying partition table reconstruction to: ${TARGET_IMAGE}"',
        "",
    ]

    for part in partition_map.partitions:
        lines.append(f"# Partition {part.index}: {part.name} ({part.fs_type or 'Unknown'})")
        lines.append(
            f'parted -s "${{TARGET_IMAGE}}" mkpart "{part.name}" {part.start_lba}s {part.end_lba}s'
        )

    lines.append("")
    lines.append('echo "Virtual partition map written to copy successfully."')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"Generated standalone partition repair script at: {output_path}")
