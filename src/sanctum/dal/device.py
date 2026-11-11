import abc
import os
from pathlib import Path
from sanctum.dal.models import DeviceInfo
from sanctum.exceptions import SanctumError

class DeviceReadError(SanctumError):
    """Raised when reading from a device fails."""
    pass

class DeviceWriteError(SanctumError):
    """Raised when a forbidden write is attempted."""
    pass

class BaseDevice(abc.ABC):
    """Abstract base class for all storage devices. Enforces read-only behavior."""
    
    def __init__(self, info: DeviceInfo):
        self.info = info

    @abc.abstractmethod
    def read_sector(self, lba: int) -> bytes:
        """Read a single sector by its Logical Block Address (LBA)."""
        pass

    def write_sector(self, lba: int, data: bytes) -> None:
        """WRITE IS DISABLED. This is a read-only DAL default behavior."""
        raise DeviceWriteError("Write functionality is strictly disabled in this implementation.")

class VirtualDevice(BaseDevice):
    """A virtual device backed by a local file (e.g., test image)."""

    def __init__(self, path: str | Path):
        path_str = str(path)
        if not os.path.exists(path_str):
            raise FileNotFoundError(f"Virtual media not found at: {path_str}")
        
        # Validate that target is a regular file
        if not os.path.isfile(path_str):
            raise ValueError(f"Virtual media target must be a regular file, got directory/special path: {path_str}")

        size = os.path.getsize(path_str)
        sector_size = 512
        if size < sector_size:
            raise ValueError(f"Virtual media file too small: {size} bytes (minimum 1 sector / {sector_size} bytes)")
        if size % sector_size != 0:
            raise ValueError(f"Virtual media file size ({size} bytes) is not aligned to sector size ({sector_size} bytes)")

        lba_count = size // sector_size
        
        info = DeviceInfo(
            path=path_str,
            serial=f"VIRTUAL-{os.path.basename(path_str)}",
            capacity_bytes=size,
            sector_size=sector_size,
            lba_count=lba_count,
            is_virtual=True
        )
        super().__init__(info)
        # Open in read/write binary mode ('r+b') ONLY for Virtual test media
        self._fd = open(path_str, "r+b")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def read_sector(self, lba: int) -> bytes:
        if lba < 0 or lba >= self.info.lba_count:
            raise DeviceReadError(f"LBA {lba} is out of bounds (max: {self.info.lba_count - 1})")
        
        self._fd.seek(lba * self.info.sector_size)
        data = self._fd.read(self.info.sector_size)
        
        if len(data) != self.info.sector_size:
            raise DeviceReadError(f"Incomplete read at LBA {lba}. Got {len(data)} bytes.")
            
        return data

    def write_sector(self, lba: int, data: bytes) -> None:
        """Writes a sector ONLY to virtual test media."""
        if lba < 0 or lba >= self.info.lba_count:
            raise DeviceWriteError(f"LBA {lba} is out of bounds (max: {self.info.lba_count - 1})")
        if len(data) != self.info.sector_size:
            raise DeviceWriteError(f"Data length mismatch. Expected {self.info.sector_size}, got {len(data)}")
            
        self._fd.seek(lba * self.info.sector_size)
        self._fd.write(data)

    def flush(self) -> None:
        """Flush buffers to disk safely."""
        try:
            self._fd.flush()
            os.fsync(self._fd.fileno())
        except OSError as e:
            raise DeviceWriteError(f"Failed to flush device buffers to storage: {e}") from e

    def close(self) -> None:
        self._fd.close()


class PhysicalDevice(BaseDevice):
    """A real physical device. Read-only access via raw paths (e.g., \\\\.\\PhysicalDriveX)."""

    def __init__(self, info: DeviceInfo):
        if info.is_virtual:
            raise ValueError("Cannot initialize PhysicalDevice with virtual info.")
        super().__init__(info)
        # Opening physical drives on Windows requires Admin privileges.
        # Enforcing 'rb' (read-binary) for safety.
        try:
            self._fd = open(info.path, "rb")
        except PermissionError as e:
            raise DeviceReadError(f"Permission denied accessing {info.path}. Run as Administrator.") from e
        except OSError as e:
            raise DeviceReadError(f"Failed to open physical device {info.path}: {e}") from e

    def read_sector(self, lba: int) -> bytes:
        if lba < 0 or lba >= self.info.lba_count:
            raise DeviceReadError(f"LBA {lba} is out of bounds (max: {self.info.lba_count - 1})")
            
        self._fd.seek(lba * self.info.sector_size)
        try:
            data = self._fd.read(self.info.sector_size)
        except OSError as e:
            raise DeviceReadError(f"Failed to read LBA {lba} from physical device: {e}") from e
            
        if len(data) != self.info.sector_size:
            raise DeviceReadError(f"Incomplete read at LBA {lba}. Got {len(data)} bytes.")
            
        return data

    def close(self) -> None:
        self._fd.close()
