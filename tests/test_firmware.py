import pytest
from pathlib import Path
from sanctum.dal import VirtualDevice, DeviceInfo
from sanctum.firmware import FirmwareSanitizer, SanitizeMethod, FirmwareSanitizationError
from sanctum.audit import AuditWriter

def get_mock_device(serial: str, tmp_path: Path) -> VirtualDevice:
    img_path = tmp_path / f"{serial}.img"
    with open(img_path, "wb") as f:
        f.write(b"\x00" * 512)
    dev = VirtualDevice(img_path)
    # Patch the serial strictly for testing adapter routing
    dev.info.serial = serial
    return dev

def test_firmware_ata_success(tmp_path: Path) -> None:
    dev = get_mock_device("ATA-123", tmp_path)
    sanitizer = FirmwareSanitizer(device=dev)
    
    # ATA mock supports BLOCK_ERASE
    result = sanitizer.sanitize(SanitizeMethod.BLOCK_ERASE)
    assert result is True
    dev.close()

def test_firmware_nvme_success(tmp_path: Path) -> None:
    dev = get_mock_device("NVME-123", tmp_path)
    sanitizer = FirmwareSanitizer(device=dev)
    
    # NVMe mock supports CRYPTO_ERASE
    result = sanitizer.sanitize(SanitizeMethod.CRYPTO_ERASE)
    assert result is True
    dev.close()

def test_firmware_scsi_success(tmp_path: Path) -> None:
    dev = get_mock_device("SCSI-123", tmp_path)
    sanitizer = FirmwareSanitizer(device=dev)
    
    # SCSI mock supports BLOCK_ERASE
    result = sanitizer.sanitize(SanitizeMethod.BLOCK_ERASE)
    assert result is True
    dev.close()

def test_firmware_unsupported_raises_error(tmp_path: Path) -> None:
    dev = get_mock_device("UNSUPPORTED-123", tmp_path)
    
    # Initialize audit writer to verify it logs the UNAVAILABLE event
    audit_path = tmp_path / "audit.log"
    audit = AuditWriter(str(audit_path))
    
    sanitizer = FirmwareSanitizer(device=dev, audit=audit)
    
    with pytest.raises(FirmwareSanitizationError, match="UNAVAILABLE"):
        sanitizer.sanitize(SanitizeMethod.BLOCK_ERASE)
        
    audit_content = audit_path.read_text(encoding="utf-8")
    assert "FIRMWARE_SANITIZE_CHECK" in audit_content
    assert "UNAVAILABLE" in audit_content
    dev.close()

def test_firmware_wrong_method_raises_error(tmp_path: Path) -> None:
    dev = get_mock_device("NVME-123", tmp_path)
    sanitizer = FirmwareSanitizer(device=dev)
    
    # NVMe mock does not support BLOCK_ERASE, only CRYPTO_ERASE
    with pytest.raises(FirmwareSanitizationError, match="UNAVAILABLE"):
        sanitizer.sanitize(SanitizeMethod.BLOCK_ERASE)
    dev.close()

def test_firmware_frozen_drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dev = get_mock_device("ATA-123", tmp_path)
    sanitizer = FirmwareSanitizer(device=dev)
    
    # Mock the adapter's detect_frozen to return FROZEN
    from sanctum.firmware.models import FirmwareStatus
    monkeypatch.setattr(sanitizer.adapter, "detect_frozen", lambda: FirmwareStatus.FROZEN)
    
    with pytest.raises(FirmwareSanitizationError, match="FROZEN"):
        sanitizer.sanitize(SanitizeMethod.BLOCK_ERASE)
    dev.close()
