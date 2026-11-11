import pytest
import datetime
from unittest.mock import MagicMock
from sanctum.dal import DeviceInfo
from sanctum.safety import SafetyGuard, SafetyError, OperationMode, CapabilityToken

@pytest.fixture
def guard() -> SafetyGuard:
    return SafetyGuard()

@pytest.fixture
def virtual_device() -> DeviceInfo:
    return DeviceInfo(
        path="/test/media.img",
        serial="VIRTUAL-media.img",
        capacity_bytes=1024,
        sector_size=512,
        lba_count=2,
        is_virtual=True
    )

@pytest.fixture
def physical_device_safe() -> DeviceInfo:
    return DeviceInfo(
        path="\\\\.\\PhysicalDrive1",
        serial="SAMSUNG-123",
        capacity_bytes=1024,
        sector_size=512,
        lba_count=2,
        is_virtual=False
    )

@pytest.fixture
def physical_device_protected() -> DeviceInfo:
    return DeviceInfo(
        path="\\\\.\\PhysicalDrive0",
        serial="BOOT-DRIVE",
        capacity_bytes=1024,
        sector_size=512,
        lba_count=2,
        is_virtual=False
    )

def test_acquire_token_success(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    token = guard.request_token(
        device=virtual_device, 
        job_id="job-1", 
        operation_id="op-1", 
        mode=OperationMode.ACQUISITION, 
        confirmed=True
    )
    assert token.is_valid()
    assert guard.validate_token(token, virtual_device, OperationMode.ACQUISITION)

def test_missing_confirmation(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    with pytest.raises(SafetyError, match="explicit confirmation is required"):
        guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=False)

def test_ambiguous_identity(guard: SafetyGuard) -> None:
    device = DeviceInfo(
        path="\\\\.\\PhysicalDrive2",
        serial="UNKNOWN",
        capacity_bytes=1024,
        lba_count=2,
        is_virtual=False
    )
    with pytest.raises(SafetyError, match="identity is ambiguous"):
        guard.request_token(device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)

def test_protected_device(guard: SafetyGuard, physical_device_protected: DeviceInfo) -> None:
    with pytest.raises(SafetyError, match="protected system/root device"):
        guard.request_token(physical_device_protected, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)

def test_mounted_device(guard: SafetyGuard, physical_device_safe: DeviceInfo) -> None:
    guard.is_mounted = MagicMock(return_value=True) # type: ignore
    with pytest.raises(SafetyError, match="currently mounted"):
        guard.request_token(physical_device_safe, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)

def test_conflicting_operation(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)
    with pytest.raises(SafetyError, match="conflicting operation is already active"):
        guard.request_token(virtual_device, "job-2", "op-2", OperationMode.SANITIZATION, confirmed=True)

def test_expired_token(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    token = guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)
    # Force expire
    token.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    
    with pytest.raises(SafetyError, match="invalid or expired"):
        guard.validate_token(token, virtual_device, OperationMode.ACQUISITION)

def test_wrong_device_binding(guard: SafetyGuard, virtual_device: DeviceInfo, physical_device_safe: DeviceInfo) -> None:
    token = guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)
    with pytest.raises(SafetyError, match="Wrong device selected"):
        guard.validate_token(token, physical_device_safe, OperationMode.ACQUISITION)

def test_wrong_operation_mode(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    token = guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)
    with pytest.raises(SafetyError, match="mode binding mismatch"):
        guard.validate_token(token, virtual_device, OperationMode.SANITIZATION)

def test_revoke_token(guard: SafetyGuard, virtual_device: DeviceInfo) -> None:
    token = guard.request_token(virtual_device, "job-1", "op-1", OperationMode.ACQUISITION, confirmed=True)
    guard.revoke_token(token)
    assert not token.is_valid()
    
    # Should be able to acquire again
    token2 = guard.request_token(virtual_device, "job-2", "op-2", OperationMode.ACQUISITION, confirmed=True)
    assert token2.is_valid()
