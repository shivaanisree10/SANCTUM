import os
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.partitions import PartitionMapper


def main():
    lab_dir = Path("test_lab")
    lab_dir.mkdir(parents=True, exist_ok=True)
    disk_path = lab_dir / "partition_demo.img"

    # Create a 4MB disk with MBR
    with open(disk_path, "wb") as f:
        f.seek(4 * 1024 * 1024 - 1)
        f.write(b"\x00")

    import struct
    # Write MBR at LBA 0 with two partitions:
    # Part 1: NTFS, start 2048, count 2000 (ends at 4047)
    # Part 2: Linux, start 4048, count 2000 (ends at 6047)
    mbr = bytearray(512)
    # Part 1
    mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\x00\x00\x00", 0x07, b"\x00\x00\x00", 2048, 2000)
    # Part 2
    mbr[462:478] = struct.pack("<B3sB3sII", 0x00, b"\x00\x00\x00", 0x83, b"\x00\x00\x00", 4048, 2000)
    mbr[510:512] = b"\x55\xaa"

    with open(disk_path, "r+b") as f:
        f.seek(0)
        f.write(mbr)

    print("=" * 65)
    print(" SANCTUM M9 PARTITION & VOLUME MAPPER DEMO")
    print("=" * 65)
    print(f"Target storage media: {disk_path}")

    vdev = VirtualDevice(disk_path)
    mapper = PartitionMapper(vdev)
    pmap = mapper.map_partitions()

    print(f"\nDiscovered Partition Scheme: {pmap.scheme.value}")
    print(f"Total Disk Sectors:          {pmap.total_disk_lbas}")
    print(f"Layout Consistent:           {pmap.is_consistent}")
    print(f"Virtually Repaired:          {pmap.is_repaired}")
    print("-" * 65)

    for p in pmap.partitions:
        print(
            f"Partition {p.index:2d}: [{p.start_lba:6d} .. {p.end_lba:6d}] "
            f"({p.sector_count:6d} sectors | {p.size_bytes // 1024:6d} KB) "
            f"Type: {p.type_id:<6s} FS: {p.fs_type or 'Unknown':<16s} "
            f"Boot: {p.bootable}"
        )

    # Expose VirtualVolumes
    volumes = mapper.get_volumes()
    print("-" * 65)
    print(f"Exposed {len(volumes)} Virtual Read-Only Volume Abstraction(s):")
    for vol in volumes:
        print(f" - Volume: {vol.info.path} | Capacity: {vol.info.capacity_bytes} bytes")

    # Generate non-destructive repair script
    script_path = lab_dir / "partition_repair_preview.sh"
    mapper.generate_repair_script(str(script_path))
    print(f"\nGenerated non-destructive repair script: {script_path}")
    print("=" * 65)

    vdev.close()


if __name__ == "__main__":
    main()
