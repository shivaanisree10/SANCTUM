import struct
import hashlib
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.carving import CarvingEngine


def main():
    lab_dir = Path("test_lab")
    lab_dir.mkdir(parents=True, exist_ok=True)
    disk_path = lab_dir / "carving_demo.img"

    # Create 2MB disk
    with open(disk_path, "wb") as f:
        f.seek(2 * 1024 * 1024 - 1)
        f.write(b"\x00")

    # 1. Embed valid PNG at LBA 16 (offset 8192)
    png_data = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00szz\xf4"
        + (b"\xAA" * 64)
        + b"IEND\xaeB`\x82"
    )

    # 2. Embed valid SQLite DB at LBA 32 (offset 16384)
    sqlite_data = bytearray(1024)
    sqlite_data[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", sqlite_data, 16, 512)
    struct.pack_into(">I", sqlite_data, 28, 2)

    # 3. Embed valid JPEG at LBA 48 (offset 24576)
    jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\x55" * 120) + b"\xff\xd9"

    with open(disk_path, "r+b") as f:
        f.seek(16 * 512)
        f.write(png_data)
        f.seek(32 * 512)
        f.write(sqlite_data)
        f.seek(48 * 512)
        f.write(jpeg_data)

    print("=" * 65)
    print(" SANCTUM M12 FILE CARVING ENGINE DEMO")
    print("=" * 65)
    print(f"Target disk: {disk_path}")

    vdev = VirtualDevice(disk_path)
    engine = CarvingEngine(config_path="config/signatures.yaml")

    print("\nExecuting streaming multi-pattern carving with Aho-Corasick...")
    report = engine.carve_device(vdev)

    print("-" * 65)
    print(f"Total Scanned:      {report.total_scanned_bytes} bytes")
    print(f"Candidate Matches:  {report.total_candidates}")
    print(f"Validated Carved:   {report.valid_carved_count}")
    print(f"Deduplicated:       {report.deduplicated_count}")
    print(f"Elapsed Time:       {report.elapsed_seconds:.4f}s")
    print("-" * 65)

    for c in report.carved_files:
        print(f"Artifact:   {c.id} ({c.format_id} / .{c.extension})")
        print(f"Location:   LBA {c.start_lba} (byte offset {c.start_byte_offset})")
        print(f"Size:       {c.size_bytes} bytes | Entropy: {c.entropy:.2f}")
        print(f"SHA-256:    {c.sha256}")
        print(f"Validation: {c.validator_notes}")
        print(f"Fragmented: {c.is_fragmented}")
        print("-" * 65)

    print("=" * 65)
    vdev.close()


if __name__ == "__main__":
    main()
