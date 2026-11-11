import hashlib
import struct
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.carving import (
    CarvingEngine,
    AhoCorasickMatcher,
    calculate_entropy,
    classify_block,
    BlockEntropyClass,
    VALIDATORS,
)


def create_blank_disk(path: Path, sector_count: int = 2048) -> None:
    with open(path, "wb") as f:
        f.seek(sector_count * 512 - 1)
        f.write(b"\x00")


# =========================================================================
# 1. SIGNATURES & MATCHER TESTS
# =========================================================================


def test_aho_corasick_matcher() -> None:
    matcher = AhoCorasickMatcher()
    matcher.add_pattern(b"\xff\xd8\xff", "JPEG")
    matcher.add_pattern(b"\x89PNG\r\n\x1a\n", "PNG")
    matcher.add_pattern(b"PK\x03\x04", "ZIP")
    matcher.compile()

    stream = b"junkdata123\xff\xd8\xffmiddlejunk\x89PNG\r\n\x1a\nendPK\x03\x04"
    matches = matcher.search(stream)

    assert len(matches) == 3
    assert matches[0] == (11, "JPEG")
    assert matches[1] == (24, "PNG")
    assert matches[2] == (35, "ZIP")


def test_entropy_and_block_classification() -> None:
    zero_block = b"\x00" * 512
    assert calculate_entropy(zero_block) == 0.0
    assert classify_block(zero_block) == BlockEntropyClass.SPARSE_ZERO

    text_block = b"The quick brown fox jumps over the lazy dog. " * 12
    assert 3.0 < calculate_entropy(text_block) < 6.0
    assert classify_block(text_block) == BlockEntropyClass.LOW_TEXT_CODE

    # High entropy / pseudo-random block
    import random
    rng = random.Random(123)
    random_block = bytes(rng.randbytes(512))
    assert calculate_entropy(random_block) > 7.0
    assert classify_block(random_block) == BlockEntropyClass.HIGH_COMPRESSED_MEDIA


# =========================================================================
# 2. STRUCTURE-AWARE VALIDATOR TESTS
# =========================================================================


def test_structure_aware_validators() -> None:
    # 1. JPEG
    valid_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\x12" * 50) + b"\xff\xd9"
    is_valid, length, _ = VALIDATORS["validate_jpeg"](valid_jpeg)
    assert is_valid is True
    assert length == len(valid_jpeg)

    # Corrupt JPEG (missing EOI)
    corrupt_jpeg = b"\xff\xd8\xff\xe0" + (b"\x12" * 50)
    is_valid, _, _ = VALIDATORS["validate_jpeg"](corrupt_jpeg)
    assert is_valid is False

    # 2. PNG
    valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa" + (b"\x00" * 16) + b"IEND\xaeB`\x82"
    is_valid, length, _ = VALIDATORS["validate_png"](valid_png)
    assert is_valid is True
    assert length == len(valid_png)

    # 3. SQLite
    sqlite_hdr = bytearray(1024)
    sqlite_hdr[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", sqlite_hdr, 16, 512)  # page size 512
    struct.pack_into(">I", sqlite_hdr, 28, 2)  # 2 pages
    is_valid, length, _ = VALIDATORS["validate_sqlite"](bytes(sqlite_hdr))
    assert is_valid is True
    assert length == 1024  # 2 * 512

    # 4. BMP
    bmp_hdr = bytearray(128)
    bmp_hdr[0:2] = b"BM"
    struct.pack_into("<I", bmp_hdr, 2, 70)  # file size 70
    struct.pack_into("<I", bmp_hdr, 14, 40)  # DIB header 40
    is_valid, length, _ = VALIDATORS["validate_bmp"](bytes(bmp_hdr[:70]))
    assert is_valid is True
    assert length == 70

    # 5. RIFF (WAV)
    riff_hdr = bytearray(64)
    riff_hdr[0:4] = b"RIFF"
    struct.pack_into("<I", riff_hdr, 4, 40)  # riff_size 40 -> total 48
    riff_hdr[8:12] = b"WAVE"
    is_valid, length, _ = VALIDATORS["validate_riff"](bytes(riff_hdr[:48]))
    assert is_valid is True
    assert length == 48

    # 6. PDF
    pdf_doc = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    is_valid, length, _ = VALIDATORS["validate_pdf"](pdf_doc)
    assert is_valid is True
    assert length == len(pdf_doc)


# =========================================================================
# 3. STREAMING CARVING ENGINE ON SYNTHETIC DISK IMAGE
# =========================================================================


def test_streaming_carver_on_synthetic_disk(tmp_path: Path) -> None:
    disk_path = tmp_path / "carve_disk.img"
    create_blank_disk(disk_path, sector_count=2048)

    # Prepare ground-truth files:
    # 1. PNG at LBA 10 (offset 5120)
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa" + (b"\x00" * 16) + b"IEND\xaeB`\x82"
    png_hash = hashlib.sha256(png_data).hexdigest()

    # 2. PDF at LBA 20 (offset 10240)
    pdf_data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
    pdf_hash = hashlib.sha256(pdf_data).hexdigest()

    # 3. SQLite DB at LBA 30 (offset 15360)
    sqlite_data = bytearray(1024)
    sqlite_data[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", sqlite_data, 16, 512)
    struct.pack_into(">I", sqlite_data, 28, 2)
    sqlite_hash = hashlib.sha256(bytes(sqlite_data)).hexdigest()

    # 4. Duplicate PNG at LBA 50 (to test content-hash deduplication)
    with open(disk_path, "r+b") as f:
        f.seek(10 * 512)
        f.write(png_data)
        f.seek(20 * 512)
        f.write(pdf_data)
        f.seek(30 * 512)
        f.write(sqlite_data)
        f.seek(50 * 512)
        f.write(png_data)  # Duplicate!

    vdev = VirtualDevice(disk_path)
    engine = CarvingEngine(config_path="config/signatures.yaml")

    report = engine.carve_device(vdev)

    assert report.total_scanned_bytes > 0
    assert report.valid_carved_count == 3  # PNG, PDF, SQLite (duplicate PNG deduplicated!)
    assert report.deduplicated_count >= 1

    carved_hashes = {c.sha256: c for c in report.carved_files}

    # Verify PNG provenance
    assert png_hash in carved_hashes
    carved_png = carved_hashes[png_hash]
    assert carved_png.format_id == "PNG"
    assert carved_png.extension == "png"
    assert carved_png.start_lba == 10
    assert carved_png.start_byte_offset == 5120
    assert carved_png.size_bytes == len(png_data)

    # Verify PDF provenance
    assert pdf_hash in carved_hashes
    carved_pdf = carved_hashes[pdf_hash]
    assert carved_pdf.format_id == "PDF"
    assert carved_pdf.start_lba == 20
    assert carved_pdf.start_byte_offset == 10240

    # Verify SQLite provenance
    assert sqlite_hash in carved_hashes
    carved_sqlite = carved_hashes[sqlite_hash]
    assert carved_sqlite.format_id == "SQLITE"
    assert carved_sqlite.start_lba == 30
    assert carved_sqlite.size_bytes == 1024

    vdev.close()


def test_bifragment_jpeg_recovery(tmp_path: Path) -> None:
    disk_path = tmp_path / "frag_disk.img"
    create_blank_disk(disk_path, sector_count=2048)

    # Build fragmented JPEG:
    # Fragment 1 (512 bytes): Header + high entropy noise
    frag1 = b"\xff\xd8\xff\xe0" + (b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 63) + b"\x00\x00\x00\x00"
    # Gap (512 bytes): All zeroes
    gap = b"\x00" * 512
    # Fragment 2 (512 bytes): Resumed high entropy + EOI \xFF\xD9
    frag2 = (b"\xfe\xdc\xba\x98\x76\x54\x32\x10" * 63) + b"\xff\xd9" + (b"\x00" * 6)

    with open(disk_path, "r+b") as f:
        f.seek(10 * 512)
        f.write(frag1)
        f.seek(11 * 512)
        f.write(gap)
        f.seek(12 * 512)
        f.write(frag2)

    vdev = VirtualDevice(disk_path)
    engine = CarvingEngine(config_path="config/signatures.yaml")
    report = engine.carve_device(vdev)

    # Should detect fragment gap and splice fragments
    jpeg_files = [f for f in report.carved_files if f.format_id == "JPEG"]
    assert len(jpeg_files) == 1
    assert jpeg_files[0].is_fragmented is True
    assert jpeg_files[0].validation_passed is True

    vdev.close()


def test_time_budget_enforcement(tmp_path: Path) -> None:
    disk_path = tmp_path / "budget_disk.img"
    create_blank_disk(disk_path, sector_count=4096)

    vdev = VirtualDevice(disk_path)
    engine = CarvingEngine(config_path="config/signatures.yaml")

    # Set very small budget (0.0001s)
    report = engine.carve_device(vdev, time_budget_seconds=0.0001)
    assert report.timed_out is True

    vdev.close()


# =========================================================================
# 4. DECODING, TRUNCATION, AND CORRUPTION TESTS
# =========================================================================


def test_jpeg_valid_truncated_and_corrupt() -> None:
    import io
    from PIL import Image, ImageDraw

    # 1. Valid real JPEG with visible content
    img = Image.new("RGB", (64, 64), color=(30, 60, 90))
    d = ImageDraw.Draw(img)
    d.rectangle([5, 5, 58, 58], fill=(200, 100, 50))
    d.text((10, 25), "TEST", fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    valid_jpg_data = buf.getvalue()

    ok, length, notes = VALIDATORS["validate_jpeg"](valid_jpg_data)
    assert ok is True
    assert length == len(valid_jpg_data)
    assert "decoded successfully" in notes

    # 2. Truncated JPEG (missing EOI)
    truncated_jpg = valid_jpg_data[: len(valid_jpg_data) // 2]
    ok_t, _, notes_t = VALIDATORS["validate_jpeg"](truncated_jpg)
    assert ok_t is False
    assert "Missing JPEG EOI" in notes_t

    # 3. Corrupted JPEG (SOF header structure corrupted)
    corrupt_hdr = bytearray(valid_jpg_data)
    sof_idx = corrupt_hdr.find(b"\xff\xc0")
    assert sof_idx != -1
    corrupt_hdr[sof_idx + 3] = 0x00  # invalid segment length
    ok_c, _, notes_c = VALIDATORS["validate_jpeg"](bytes(corrupt_hdr))
    assert ok_c is False
    assert "JPEG decoding failed" in notes_c


def test_png_valid_truncated_and_corrupt() -> None:
    import io
    from PIL import Image, ImageDraw

    # 1. Valid real PNG with visible content
    img = Image.new("RGBA", (64, 64), color=(20, 80, 40, 255))
    d = ImageDraw.Draw(img)
    d.ellipse([10, 10, 54, 54], fill=(255, 200, 0, 255))
    d.text((15, 25), "PNG", fill=(0, 0, 0, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    valid_png_data = buf.getvalue()

    ok, length, notes = VALIDATORS["validate_png"](valid_png_data)
    assert ok is True
    assert length == len(valid_png_data)
    assert "decoded successfully" in notes

    # 2. Truncated PNG (missing IEND)
    truncated_png = valid_png_data[: len(valid_png_data) // 2]
    ok_t, _, notes_t = VALIDATORS["validate_png"](truncated_png)
    assert ok_t is False
    assert "Incomplete or corrupt PNG" in notes_t

    # 3. Corrupted PNG CRC
    corrupt_png = bytearray(valid_png_data)
    idat_pos = corrupt_png.find(b"IDAT")
    assert idat_pos != -1
    corrupt_png[idat_pos + 6] ^= 0xFF
    ok_c, _, notes_c = VALIDATORS["validate_png"](bytes(corrupt_png))
    assert ok_c is False
    assert "CRC" in notes_c or "failed" in notes_c


def test_pdf_valid_truncated_and_corrupt() -> None:
    # 1. Valid PDF with objects and cross references
    valid_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n180\n%%EOF\n"
    )
    ok, length, notes = VALIDATORS["validate_pdf"](valid_pdf)
    assert ok is True
    assert length == len(valid_pdf)

    # 2. Truncated PDF (missing %%EOF)
    truncated_pdf = valid_pdf[:120]
    ok_t, _, notes_t = VALIDATORS["validate_pdf"](truncated_pdf)
    assert ok_t is False
    assert "Missing PDF %%EOF" in notes_t

    # 3. Corrupted PDF (missing obj structure)
    corrupted_pdf = b"%PDF-1.4\nplain text payload without object markers\n%%EOF\n"
    ok_c, _, notes_c = VALIDATORS["validate_pdf"](corrupted_pdf)
    assert ok_c is False
    assert "PDF structural validation failed" in notes_c
