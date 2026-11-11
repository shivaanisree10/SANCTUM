import random
from typing import List, Dict, Any, Optional
from sanctum.dal.device import BaseDevice, DeviceReadError, DeviceWriteError
from sanctum.dal.models import DeviceInfo


class ChaosFaultInjector:
    """
    Controlled Fault and Corruption Injection Framework.
    Simulates:
    - Bad sector / read errors on designated LBA ranges
    - Write protected / I/O errors on targeted sectors
    - Controlled bit-flips / corruptions for testing parser resilience
    - Latency / intermittent failures
    """

    def __init__(self):
        self.bad_read_lbas: set = set()
        self.bad_write_lbas: set = set()
        self.corrupted_lbas: Dict[int, bytes] = {}

    def inject_bad_read_sectors(self, lba_range: range) -> None:
        """Designate LBAs that will trigger DeviceReadError on read."""
        self.bad_read_lbas.update(lba_range)

    def inject_bad_write_sectors(self, lba_range: range) -> None:
        """Designate LBAs that will trigger DeviceWriteError on write."""
        self.bad_write_lbas.update(lba_range)

    def inject_sector_corruption(self, lba: int, corrupted_data: bytes) -> None:
        """Substitute corrupted data on designated LBA."""
        self.corrupted_lbas[lba] = corrupted_data

    def check_read(self, lba: int) -> Optional[bytes]:
        if lba in self.bad_read_lbas:
            raise DeviceReadError(f"Simulated hardware read error at LBA {lba}")
        return self.corrupted_lbas.get(lba)

    def check_write(self, lba: int) -> None:
        if lba in self.bad_write_lbas:
            raise DeviceWriteError(f"Simulated hardware write failure at LBA {lba}")


class ChaosVirtualDevice(BaseDevice):
    """
    Virtual storage device equipped with a ChaosFaultInjector.
    Used in validation laboratory to verify error-tolerant acquisition,
    post-acquisition error maps, and fail-closed safety handling.
    """

    def __init__(self, serial: str = "CHAOS-VIRT-001", size_bytes: int = 10485760, sector_size: int = 512):
        info = DeviceInfo(
            path="virtual://chaos_device",
            serial=serial,
            capacity_bytes=size_bytes,
            sector_size=sector_size,
            lba_count=size_bytes // sector_size,
            is_virtual=True,
        )
        super().__init__(info)
        self.storage = bytearray(size_bytes)
        self.fault_injector = ChaosFaultInjector()

    def read_sector(self, lba: int) -> bytes:
        if lba < 0 or lba >= self.info.lba_count:
            raise DeviceReadError(f"LBA {lba} out of bounds.")
        corrupted = self.fault_injector.check_read(lba)
        if corrupted:
            return corrupted
        offset = lba * self.info.sector_size
        return bytes(self.storage[offset : offset + self.info.sector_size])

    def write_sector(self, lba: int, data: bytes) -> None:
        if lba < 0 or lba >= self.info.lba_count:
            raise DeviceWriteError(f"LBA {lba} out of bounds.")
        self.fault_injector.check_write(lba)
        if len(data) != self.info.sector_size:
            raise DeviceWriteError(f"Invalid sector payload size: {len(data)}")
        offset = lba * self.info.sector_size
        self.storage[offset : offset + self.info.sector_size] = data
