import os
import zipfile
import pytest
from pathlib import Path

from sanctum.dal import VirtualDevice, BaseDevice, DeviceInfo
from sanctum.dal.device import DeviceReadError
from sanctum.safety import SafetyGuard, OperationMode
from sanctum.safety.guard import SafetyError
from sanctum.audit import AuditWriter
from sanctum.acquisition import (
    AcquisitionEngine,
    AcquisitionConfig,
    ImageFormat,
    WriteBlockedDevice,
    WriteBlockedError,
    assert_write_blocking,
    WriteCounterMonitor,
)


class FaultyVirtualDevice(BaseDevice):
    """Simulates a storage device with physical bad sectors at specific LBAs."""

    def __init__(self, backing_file: Path, bad_lbas: set[int]):
        size = os.path.getsize(backing_file)
        sector_size = 512
        lba_count = size // sector_size
        info = DeviceInfo(
            path=str(backing_file),
            serial=f"FAULTY-{backing_file.name}",
            capacity_bytes=size,
            sector_size=sector_size,
            lba_count=lba_count,
            is_virtual=True,
        )
        super().__init__(info)
        self.backing_file = backing_file
        self.bad_lbas = bad_lbas
        self._fd = open(backing_file, "rb")

    def read_sector(self, lba: int) -> bytes:
        if lba in self.bad_lbas:
            raise DeviceReadError(f"I/O Device Hardware Error: Uncorrectable ECC error at LBA {lba}")
        self._fd.seek(lba * self.info.sector_size)
        return self._fd.read(self.info.sector_size)

    def close(self) -> None:
        self._fd.close()


def create_test_source_media(file_path: Path, sector_count: int = 16) -> bytes:
    """Creates disposable test media with known deterministic data."""
    # Pattern: sector index encoded into each sector
    content = bytearray()
    for i in range(sector_count):
        sector = (f"SECTOR_{i:04d}_DATA_".encode("ascii") * 32)[:512]
        content.extend(sector)
    file_path.write_bytes(content)
    return bytes(content)


def test_software_write_blocking_assertion(tmp_path: Path) -> None:
    src_file = tmp_path / "src.img"
    create_test_source_media(src_file, 4)
    vdev = VirtualDevice(src_file)

    blocked = WriteBlockedDevice(vdev)

    # 1. Deliberate test-write assertion must pass
    assert assert_write_blocking(blocked) is True

    # 2. Direct write attempt must be intercepted and blocked
    with pytest.raises(WriteBlockedError):
        blocked.write_sector(0, b"\x00" * 512)

    assert blocked.blocked_write_attempts >= 1
    assert blocked.actual_writes == 0

    blocked.close()


def test_normal_raw_acquisition(tmp_path: Path) -> None:
    src_file = tmp_path / "src_normal.img"
    out_img = tmp_path / "acquired.raw"
    audit_file = tmp_path / "audit.log"

    raw_data = create_test_source_media(src_file, sector_count=16)  # 8KB
    vdev = VirtualDevice(src_file)

    guard = SafetyGuard()
    token = guard.request_token(vdev.info, "JOB-ACQ-1", "OP-1", OperationMode.ACQUISITION, confirmed=True)
    audit = AuditWriter(str(audit_file))

    config = AcquisitionConfig(
        output_path=str(out_img),
        format=ImageFormat.RAW,
        case_id="CASE-2026",
        evidence_id="ITEM-001",
        examiner="FORENSIC-TECH",
    )

    engine = AcquisitionEngine(vdev, guard, token, audit, config)
    result = engine.run()

    assert result.success is True
    assert result.status == "SUCCESS"
    assert result.metadata.source_hashes_match is True
    assert result.metadata.image_verification_passed is True
    assert result.metadata.write_counter_delta == 0
    assert result.metadata.write_blocking_verified is True
    assert result.metadata.total_bad_sectors == 0

    # Verify acquired image bytes match source perfectly
    assert out_img.exists()
    assert out_img.read_bytes() == raw_data

    # Verify metadata JSON was created
    meta_json = tmp_path / "acquired.raw.meta.json"
    assert meta_json.exists()

    # Verify audit log recorded ACQUISITION_START, WRITE_BLOCK_VERIFIED, ACQUISITION_END
    audit_log_text = audit_file.read_text(encoding="utf-8")
    assert "ACQUISITION_START" in audit_log_text
    assert "WRITE_BLOCK_VERIFIED" in audit_log_text
    assert "ACQUISITION_END" in audit_log_text

    vdev.close()


def test_segmented_raw_acquisition(tmp_path: Path) -> None:
    src_file = tmp_path / "src_segmented.img"
    out_base = tmp_path / "acquired_split.raw"
    audit_file = tmp_path / "audit.log"

    raw_data = create_test_source_media(src_file, sector_count=16)  # 8192 bytes
    vdev = VirtualDevice(src_file)

    guard = SafetyGuard()
    token = guard.request_token(vdev.info, "JOB-ACQ-SEG", "OP-1", OperationMode.ACQUISITION, confirmed=True)
    audit = AuditWriter(str(audit_file))

    # Split into 2048 byte segments -> expect 4 segments (.001, .002, .003, .004)
    config = AcquisitionConfig(
        output_path=str(out_base),
        format=ImageFormat.RAW,
        segment_size_bytes=2048,
    )

    engine = AcquisitionEngine(vdev, guard, token, audit, config)
    result = engine.run()

    assert result.success is True
    assert len(result.metadata.segments) == 4

    # Reassemble segments and compare
    reassembled = bytearray()
    for seg_path in result.metadata.segments:
        assert Path(seg_path).exists()
        reassembled.extend(Path(seg_path).read_bytes())

    assert bytes(reassembled) == raw_data
    vdev.close()


def test_injected_read_errors_and_error_map(tmp_path: Path) -> None:
    src_file = tmp_path / "src_bad_sectors.img"
    out_img = tmp_path / "acquired_faulty.raw"
    audit_file = tmp_path / "audit.log"

    raw_data = create_test_source_media(src_file, sector_count=10)
    # Inject bad sectors at LBA 3 and LBA 7
    faulty_dev = FaultyVirtualDevice(src_file, bad_lbas={3, 7})

    guard = SafetyGuard()
    token = guard.request_token(faulty_dev.info, "JOB-ACQ-ERR", "OP-1", OperationMode.ACQUISITION, confirmed=True)
    audit = AuditWriter(str(audit_file))

    config = AcquisitionConfig(
        output_path=str(out_img),
        format=ImageFormat.RAW,
        max_retries=2,
    )

    engine = AcquisitionEngine(faulty_dev, guard, token, audit, config)
    result = engine.run()

    assert result.success is True
    assert result.status == "COMPLETED_WITH_ERRORS"
    assert result.error_map.total_bad_sectors == 2
    assert result.error_map.total_bad_bytes == 1024
    assert result.metadata.source_hashes_match is True
    assert result.metadata.write_counter_delta == 0

    # Verify persistent error map file exists and has correct bad LBAs
    error_map_file = Path(result.metadata.error_map_file)
    assert error_map_file.exists()
    error_map_content = error_map_file.read_text(encoding="utf-8")
    assert "3" in error_map_content
    assert "7" in error_map_content

    # Verify zero-substitution in output image
    acquired_data = out_img.read_bytes()
    assert len(acquired_data) == len(raw_data)  # Exact geometry and size preserved

    # LBA 3 (bytes 1536:2048) must be all zeros
    lba_3_slice = acquired_data[3 * 512 : 4 * 512]
    assert lba_3_slice == b"\x00" * 512

    # LBA 7 (bytes 3584:4096) must be all zeros
    lba_7_slice = acquired_data[7 * 512 : 8 * 512]
    assert lba_7_slice == b"\x00" * 512

    # Normal sectors like LBA 0 must match original data
    assert acquired_data[:512] == raw_data[:512]

    faulty_dev.close()


def test_e01_acquisition(tmp_path: Path) -> None:
    src_file = tmp_path / "src_e01.img"
    out_img = tmp_path / "acquired_image.E01"
    audit_file = tmp_path / "audit.log"

    create_test_source_media(src_file, sector_count=8)
    vdev = VirtualDevice(src_file)

    guard = SafetyGuard()
    token = guard.request_token(vdev.info, "JOB-E01", "OP-1", OperationMode.ACQUISITION, confirmed=True)
    audit = AuditWriter(str(audit_file))

    config = AcquisitionConfig(
        output_path=str(out_img),
        format=ImageFormat.E01,
        case_id="CASE-E01-99",
    )

    engine = AcquisitionEngine(vdev, guard, token, audit, config)
    result = engine.run()

    assert result.success is True
    assert out_img.exists()
    assert result.metadata.format == ImageFormat.E01
    assert result.metadata.source_hashes_match is True
    vdev.close()


def test_aff4_acquisition_container_verification(tmp_path: Path) -> None:
    src_file = tmp_path / "src_aff4.img"
    out_aff4 = tmp_path / "acquired_image.aff4"
    audit_file = tmp_path / "audit.log"

    raw_data = create_test_source_media(src_file, sector_count=8)
    vdev = VirtualDevice(src_file)

    guard = SafetyGuard()
    token = guard.request_token(vdev.info, "JOB-AFF4", "OP-1", OperationMode.ACQUISITION, confirmed=True)
    audit = AuditWriter(str(audit_file))

    config = AcquisitionConfig(
        output_path=str(out_aff4),
        format=ImageFormat.AFF4,
        evidence_id="EVID-AFF4-42",
    )

    engine = AcquisitionEngine(vdev, guard, token, audit, config)
    result = engine.run()

    assert result.success is True
    assert out_aff4.exists()
    assert result.metadata.format == ImageFormat.AFF4

    # Verify that the generated AFF4 container is a valid zip with RDF turtle and exact data.raw
    with zipfile.ZipFile(out_aff4, "r") as zf:
        namelist = zf.namelist()
        assert "version.txt" in namelist
        assert "information.turtle" in namelist
        assert "data.raw" in namelist
        # Read back data.raw from container and verify it matches source
        container_data = zf.read("data.raw")
        assert container_data == raw_data

    vdev.close()


def test_safety_guard_refuses_wrong_mode(tmp_path: Path) -> None:
    src_file = tmp_path / "src_safety.img"
    create_test_source_media(src_file, 4)
    vdev = VirtualDevice(src_file)

    guard = SafetyGuard()
    # Issue a SANITIZATION token instead of ACQUISITION
    token = guard.request_token(vdev.info, "JOB-WRONG-MODE", "OP-1", OperationMode.SANITIZATION, confirmed=True)
    audit = AuditWriter(str(tmp_path / "audit.log"))

    config = AcquisitionConfig(output_path=str(tmp_path / "out.raw"))

    # Passing SANITIZATION token to AcquisitionEngine must fail closed!
    with pytest.raises(SafetyError, match="mode binding mismatch"):
        AcquisitionEngine(vdev, guard, token, audit, config)

    vdev.close()
