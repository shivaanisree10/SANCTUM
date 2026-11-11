import pytest
from pathlib import Path
from sanctum.dal import VirtualDevice, DeviceInfo, DeviceReadError, DeviceWriteError
from sanctum.dal.enumerator import enumerate_virtual_devices

def create_dummy_image(path: Path, size_bytes: int) -> None:
    """Create a dummy file with specific size for testing."""
    with open(path, "wb") as f:
        # Write first sector: 512 bytes of 'A'
        f.write(b"A" * 512)
        # Pad the rest with 0
        if size_bytes > 512:
            f.seek(size_bytes - 1)
            f.write(b"\0")

def test_virtual_device_info(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    size = 1024 * 1024  # 1MB
    create_dummy_image(img_path, size)
    
    device = VirtualDevice(img_path)
    info = device.info
    assert info.capacity_bytes == size
    assert info.sector_size == 512
    assert info.lba_count == size // 512
    assert info.is_virtual is True
    assert "test.img" in info.serial
    device.close()

def test_virtual_device_read(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    size = 1024  # 2 sectors
    create_dummy_image(img_path, size)
    
    device = VirtualDevice(img_path)
    
    # Read first sector
    sector_0 = device.read_sector(0)
    assert len(sector_0) == 512
    assert sector_0 == b"A" * 512
    
    # Read second sector
    sector_1 = device.read_sector(1)
    assert len(sector_1) == 512
    assert sector_1 == b"\0" * 512
    device.close()

def test_virtual_device_out_of_bounds(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    size = 512  # 1 sector
    create_dummy_image(img_path, size)
    
    device = VirtualDevice(img_path)
    with pytest.raises(DeviceReadError):
        device.read_sector(1)  # out of bounds
    device.close()

def test_virtual_device_write_success(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    create_dummy_image(img_path, 512)
    
    device = VirtualDevice(img_path)
    device.write_sector(0, b"B" * 512)
    data = device.read_sector(0)
    assert data == b"B" * 512
    device.close()

def test_enumerate_virtual(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    create_dummy_image(img_path, 1024)
    
    devices = enumerate_virtual_devices(str(img_path))
    assert len(devices) == 1
    assert devices[0].is_virtual is True
    assert devices[0].lba_count == 2
