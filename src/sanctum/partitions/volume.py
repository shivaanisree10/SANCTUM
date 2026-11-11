from sanctum.dal import BaseDevice, DeviceInfo
from sanctum.dal.device import DeviceReadError, DeviceWriteError
from sanctum.partitions.models import PartitionEntry


class VirtualVolume(BaseDevice):
    """
    Virtual Read-Only Volume Abstraction.
    Presents an individual partition as an isolated, addressable storage device
    without writing or modifying any data on the source image.
    """

    def __init__(self, target_device: BaseDevice, entry: PartitionEntry):
        self.target_device = target_device
        self.entry = entry

        # Build virtual device info bounded to the partition
        info = DeviceInfo(
            path=f"{target_device.info.path}:part{entry.index}",
            serial=f"{target_device.info.serial}-P{entry.index}",
            capacity_bytes=entry.size_bytes,
            sector_size=target_device.info.sector_size,
            lba_count=entry.sector_count,
            is_virtual=True,
        )
        super().__init__(info)

    def read_sector(self, relative_lba: int) -> bytes:
        """Reads sector relative to partition start LBA."""
        if relative_lba < 0 or relative_lba >= self.info.lba_count:
            raise DeviceReadError(
                f"Relative LBA {relative_lba} out of volume bounds (max: {self.info.lba_count - 1})"
            )

        absolute_lba = self.entry.start_lba + relative_lba
        return self.target_device.read_sector(absolute_lba)

    def write_sector(self, lba: int, data: bytes) -> None:
        """Enforces absolute read-only behavior."""
        raise DeviceWriteError("Writing to a VirtualVolume is strictly forbidden.")

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
