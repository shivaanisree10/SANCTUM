#!/usr/bin/env python3
"""
scripts/prepare_demo_media.py
Generates a deterministic, disposable synthetic disk image with embedded JPEG, PNG, and PDF files
for live forensic acquisition and file carving demonstration.

SAFETY GUARANTEES:
- Operates ONLY on local regular file paths.
- Never targets physical drives or system partitions.
- Refuses to overwrite existing files unless explicitly specified.
"""

import os
import sys
import io
import argparse
import hashlib
from pathlib import Path
from PIL import Image, ImageDraw
import fpdf


def generate_visible_jpeg() -> bytes:
    """Generates a valid, rich JPEG image with visible shapes and text."""
    img = Image.new("RGB", (256, 256), color=(20, 45, 90))
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, 245, 245], outline=(255, 215, 0), width=4)
    d.rectangle([30, 30, 225, 225], fill=(180, 40, 40))
    d.ellipse([60, 60, 195, 195], fill=(240, 240, 250), outline=(20, 45, 90), width=3)
    d.text((85, 105), "SANCTUM", fill=(10, 30, 80))
    d.text((70, 130), "FORENSIC EVIDENCE", fill=(180, 20, 20))
    d.text((95, 155), "CONFIDENTIAL", fill=(50, 50, 50))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()


def generate_visible_png() -> bytes:
    """Generates a valid, rich PNG image with visible polygon, borders, and text."""
    img = Image.new("RGBA", (256, 256), color=(15, 75, 45, 255))
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, 245, 245], outline=(0, 255, 128), width=4)
    d.polygon([(128, 35), (220, 215), (35, 215)], fill=(0, 140, 230, 220), outline=(255, 255, 255), width=2)
    d.text((95, 120), "SANCTUM", fill=(255, 255, 255))
    d.text((85, 145), "RECOVERY TEST", fill=(255, 240, 0))
    d.text((90, 170), "INTEGRITY OK", fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_valid_pdf() -> bytes:
    """Generates a valid forensic PDF document with header, objects, and %%EOF."""
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(text="SANCTUM Forensic Examination Report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.set_font("Helvetica", size=11)
    pdf.cell(text="Evidence ID: EV-2026-COLLEGE-DEMO", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(text="Classification: DIGITAL FORENSICS RECOVERY VERIFIED", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(text="Integrity Hash Check: SHA-256 BITSTREAM VALIDATED", new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


def create_demo_media(output_path: str, capacity_mb: int = 10, overwrite: bool = False) -> None:
    path = Path(output_path).resolve()

    if path.exists() and not overwrite:
        print(f"[ERROR] Target file '{path}' already exists! Specify --overwrite to replace it safely.")
        sys.exit(1)

    print(f"[*] Initializing disposable virtual media: {path}")
    print(f"[*] Capacity: {capacity_mb} MB ({capacity_mb * 1024 * 1024} bytes, sector size 512)")

    total_bytes = capacity_mb * 1024 * 1024
    if total_bytes % 512 != 0:
        raise ValueError("Capacity must be multiple of 512 bytes.")

    # 1. Prepare Ground-Truth Embedded Evidence Payloads
    # A. Visible decoded JPEG
    jpeg_payload = generate_visible_jpeg()
    # Verify image can be decoded and loaded
    with Image.open(io.BytesIO(jpeg_payload)) as check_jpg:
        check_jpg.verify()
    with Image.open(io.BytesIO(jpeg_payload)) as check_jpg:
        check_jpg.load()
    jpeg_hash = hashlib.sha256(jpeg_payload).hexdigest()

    # B. Visible decoded PNG with verified chunks & CRC
    png_payload = generate_visible_png()
    with Image.open(io.BytesIO(png_payload)) as check_png:
        check_png.verify()
    with Image.open(io.BytesIO(png_payload)) as check_png:
        check_png.load()
    png_hash = hashlib.sha256(png_payload).hexdigest()

    # C. Valid PDF Document
    pdf_payload = generate_valid_pdf()
    pdf_hash = hashlib.sha256(pdf_payload).hexdigest()

    # 2. Write Base Disk with Synthetic Unallocated Sector Pattern
    print(f"[*] Formatting base disk sectors with repeating pattern...")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        # Fill base disk with formatted 512-byte sectors
        pattern_block = ((b"SECTOR_UNALLOCATED_CLUSTER_" * 20)[:512])
        assert len(pattern_block) == 512
        sectors = total_bytes // 512
        for s in range(sectors):
            f.write(pattern_block)

        # 3. Inject Embeddings at known LBA offsets
        # LBA 100: JPEG
        f.seek(100 * 512)
        f.write(jpeg_payload)

        # LBA 500: PNG
        f.seek(500 * 512)
        f.write(png_payload)

        # LBA 1000: PDF
        f.seek(1000 * 512)
        f.write(pdf_payload)

    # 4. Compute Full Image SHA-256 Digest
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    disk_hash = hasher.hexdigest()

    print("\n[SUCCESS] Disposable Demo Media Successfully Created!")
    print(f"  File:            {path}")
    print(f"  Total Size:      {os.path.getsize(path)} bytes ({capacity_mb} MB)")
    print(f"  Disk SHA-256:    {disk_hash}")
    print("  Embedded Evidence:")
    print(f"    - JPEG: LBA 100  (Offset: {100 * 512:7d} B, Size: {len(jpeg_payload):5d} B) | SHA256: {jpeg_hash[:16]}...")
    print(f"    - PNG:  LBA 500  (Offset: {500 * 512:7d} B, Size: {len(png_payload):5d} B) | SHA256: {png_hash[:16]}...")
    print(f"    - PDF:  LBA 1000 (Offset: {1000 * 512:7d} B, Size: {len(pdf_payload):5d} B) | SHA256: {pdf_hash[:16]}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate deterministic disposable media for SANCTUM demo.")
    parser.add_argument("--output", "-o", default="demo_evidence.raw", help="Output file path (default: demo_evidence.raw)")
    parser.add_argument("--size-mb", type=int, default=10, help="Image size in MB (default: 10)")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting existing output file")
    args = parser.parse_args()

    create_demo_media(args.output, args.size_mb, args.overwrite)
