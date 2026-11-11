import os
import time
from pathlib import Path

from sanctum.dal import VirtualDevice
from sanctum.safety import SafetyGuard, OperationMode
from sanctum.audit import AuditWriter
from sanctum.acquisition import (
    AcquisitionEngine,
    AcquisitionConfig,
    ImageFormat,
)


def main():
    lab_dir = Path("test_lab")
    lab_dir.mkdir(parents=True, exist_ok=True)

    src_img = lab_dir / "media.img"
    if not src_img.exists():
        # Generate 1MB test media
        src_img.write_bytes(b"\x5A" * (1024 * 1024))

    out_raw = lab_dir / "acquired_evidence.raw"
    audit_path = lab_dir / "audit.log"

    print("=" * 60)
    print(" SANCTUM M8 FORENSIC ACQUISITION DEMO")
    print("=" * 60)
    print(f"Source media: {src_img}")
    print(f"Destination:  {out_raw}")

    device = VirtualDevice(src_img)
    guard = SafetyGuard()
    token = guard.request_token(
        device.info,
        job_id="CASE-2026-DEMO",
        operation_id="ACQ-OP-01",
        mode=OperationMode.ACQUISITION,
        confirmed=True,
    )
    audit = AuditWriter(str(audit_path))

    config = AcquisitionConfig(
        output_path=str(out_raw),
        format=ImageFormat.RAW,
        case_id="CASE-2026-001",
        evidence_id="ITEM-001",
        examiner="FORENSIC-EXAMINER",
        description="Forensic Raw Bitstream Image of Test Media",
    )

    engine = AcquisitionEngine(device, guard, token, audit, config)

    def on_progress(pct, current_lba, total_lbas):
        print(f"\rProgress: {pct:6.2f}% | LBA {current_lba}/{total_lbas}", end="")

    start_time = time.time()
    print("\nStarting bitstream acquisition with Software Write-Blocker...")
    result = engine.run(progress_callback=on_progress)
    elapsed = time.time() - start_time

    print(f"\n\nAcquisition finished in {elapsed:.2f}s with status: {result.status}")
    print("-" * 60)
    print(f"Pre-Acquisition Source SHA-256:  {result.metadata.pre_source_sha256}")
    print(f"Post-Acquisition Source SHA-256: {result.metadata.post_source_sha256}")
    print(f"Acquired Image SHA-256:          {result.metadata.image_sha256}")
    print(f"Source Unaltered:                {result.metadata.source_hashes_match}")
    print(f"Write Counter Delta:             {result.metadata.write_counter_delta}")
    print(f"Write Blocking Verified:         {result.metadata.write_blocking_verified}")
    print(f"Bad Sectors Substituted:         {result.metadata.total_bad_sectors}")
    print(f"Metadata File:                   {result.metadata.output_path if hasattr(result.metadata, 'output_path') else config.output_path + '.meta.json'}")
    print("=" * 60)

    device.close()


if __name__ == "__main__":
    main()
