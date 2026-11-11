import os
import struct
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.fs import default_fs_registry, FATParser, NTFSParser, ExtParser, ExFATParser, APFSParser


def main():
    lab_dir = Path("test_lab")
    lab_dir.mkdir(parents=True, exist_ok=True)
    disk_path = lab_dir / "fs_demo.img"

    # Create synthetic FAT16 filesystem for demo
    with open(disk_path, "wb") as f:
        f.seek(2048 * 512 - 1)
        f.write(b"\x00")

    vbr = bytearray(512)
    vbr[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", vbr, 11, 512)
    vbr[13] = 2  # sec_per_cluster
    struct.pack_into("<H", vbr, 14, 4)  # reserved
    vbr[16] = 2  # num_fats
    struct.pack_into("<H", vbr, 17, 64)  # root_entries
    struct.pack_into("<H", vbr, 19, 2048)  # total_sectors
    struct.pack_into("<H", vbr, 22, 8)  # sec_per_fat
    vbr[54:62] = b"FAT16   "
    vbr[510:512] = b"\x55\xaa"

    root_sector = bytearray(512)
    # Allocated file: EVIDENCE.TXT
    root_sector[0:11] = b"EVIDENCEDAT"
    root_sector[11] = 0x20
    struct.pack_into("<H", root_sector, 26, 2)
    struct.pack_into("<I", root_sector, 28, 26)

    # Deleted file: _DELETED.LOG
    root_sector[32] = 0xE5
    root_sector[33:40] = b"DELETED"
    root_sector[40:43] = b"LOG"
    root_sector[43] = 0x20
    struct.pack_into("<H", root_sector, 58, 3)
    struct.pack_into("<I", root_sector, 60, 48)

    # Cluster 2 content
    cluster_2 = b"SANCTUM FORENSIC FILE DATA" + (b"\x00" * 998)

    # FAT table
    fat_table = bytearray(512)
    struct.pack_into("<H", fat_table, 0, 0xFFF8)
    struct.pack_into("<H", fat_table, 2, 0xFFFF)
    struct.pack_into("<H", fat_table, 4, 0xFFFF)
    struct.pack_into("<H", fat_table, 6, 0xFFFF)

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(vbr)
        f.seek(4 * 512)
        f.write(fat_table)
        f.seek(20 * 512)
        f.write(root_sector)
        f.seek(24 * 512)
        f.write(cluster_2)

    print("=" * 65)
    print(" SANCTUM M10 FORENSIC FILE SYSTEM PARSER DEMO")
    print("=" * 65)
    print(f"Target device image: {disk_path}")

    vdev = VirtualDevice(disk_path)

    # 1. Probe & mount via registry
    parser, confidence = default_fs_registry.detect_and_mount(vdev)
    print(f"\nAuto-Detected Filesystem: {parser.__class__.__name__}")
    print(f"Confidence Score:         {confidence:.2f}")
    print("-" * 65)

    # 2. List allocated
    allocated = parser.list_allocated()
    print(f"Allocated Files ({len(allocated)}):")
    for f in allocated:
        print(f"  [+] {f.path} ({f.size_bytes} bytes)")
        content = parser.read_file_data(f)
        print(f"      Data preview: {content[:32]}")

    # 3. List deleted
    deleted = parser.list_deleted()
    print(f"\nDeleted/Recoverable Files ({len(deleted)}):")
    for f in deleted:
        print(f"  [x] {f.path} ({f.size_bytes} bytes) [DELETED]")

    # 4. Unallocated extents
    extents = parser.get_unallocated_extents()
    print(f"\nUnallocated Extents ({len(extents)}):")
    for ext in extents[:5]:
        print(f"  [~] LBA {ext.start_lba}..{ext.start_lba + ext.sector_count - 1} ({ext.size_bytes // 1024} KB)")

    print("=" * 65)
    vdev.close()


if __name__ == "__main__":
    main()
