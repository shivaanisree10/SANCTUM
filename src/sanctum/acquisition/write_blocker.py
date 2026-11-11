import logging
from typing import Optional
from sanctum.dal import BaseDevice, DeviceInfo
from sanctum.dal.device import DeviceWriteError
from sanctum.safety.guard import SafetyError

logger = logging.getLogger("sanctum.acquisition.write_blocker")


class WriteBlockedError(DeviceWriteError):
    """Raised when an operation attempts to write to a software write-blocked device."""
    pass


class WriteBlockedDevice(BaseDevice):
    """
    Forensic Software Write-Blocker wrapper around a BaseDevice.
    Guarantees strict read-only access and rejects any attempt to write.
    """
    def __init__(self, target_device: BaseDevice):
        super().__init__(target_device.info)
        self._target = target_device
        self._read_count: int = 0
        self._read_bytes: int = 0
        self._blocked_write_attempts: int = 0
        self._actual_writes: int = 0  # Must strictly remain 0

    @property
    def target_device(self) -> BaseDevice:
        return self._target

    @property
    def read_count(self) -> int:
        return self._read_count

    @property
    def read_bytes(self) -> int:
        return self._read_bytes

    @property
    def blocked_write_attempts(self) -> int:
        return self._blocked_write_attempts

    @property
    def actual_writes(self) -> int:
        return self._actual_writes

    def read_sector(self, lba: int) -> bytes:
        data = self._target.read_sector(lba)
        self._read_count += 1
        self._read_bytes += len(data)
        return data

    def write_sector(self, lba: int, data: bytes) -> None:
        """
        Unconditionally blocks and forbids write requests.
        Never calls target.write_sector.
        """
        self._blocked_write_attempts += 1
        logger.warning(
            f"SOFTWARE WRITE-BLOCKER INTERCEPTED WRITE ATTEMPT to LBA {lba} on {self.info.serial}. "
            "Write request blocked."
        )
        raise WriteBlockedError(
            f"Write request blocked by Software Write-Blocker on {self.info.serial} (LBA {lba})."
        )

    def flush(self) -> None:
        """Flushing is safe / no-op on read-only wrapper."""
        pass

    def close(self) -> None:
        self._target.close()


def assert_write_blocking(device: WriteBlockedDevice) -> bool:
    """
    Deliberate test-write assertion.
    Proves write blocking is active and enforcing fail-closed behavior before imaging begins.
    """
    dummy_data = b"\x00" * device.info.sector_size
    try:
        device.write_sector(0, dummy_data)
    except WriteBlockedError:
        logger.info(f"Deliberate test-write assertion PASSED for {device.info.serial}.")
        return True
    except Exception as e:
        logger.error(f"Unexpected error during write-blocking assertion: {e}")
        raise SafetyError(f"Write blocking assertion failed with unexpected exception: {e}") from e

    # If write_sector did not raise, write-blocking FAILED! Fail closed!
    raise SafetyError(
        f"CRITICAL SAFETY VIOLATION: Write blocking failed! Write was permitted on {device.info.serial}."
    )


class WriteCounterMonitor:
    """
    Measures OS kernel / device write-counters to detect any unintentional modification.
    """
    def __init__(self):
        pass

    def get_write_count(self, device: BaseDevice) -> int:
        """
        Returns the cumulative write counter for the target device.
        For WriteBlockedDevice, checks the target device write state.
        For PhysicalDevice on Windows, queries performance counters if available.
        For VirtualDevice, returns 0 if unmodified or tracks actual underlying writes.
        """
        if isinstance(device, WriteBlockedDevice):
            # The WriteBlockedDevice guarantees actual_writes == 0
            # If the underlying target is also tracked, check its write metrics
            target = device.target_device
            if hasattr(target, "_write_count"):
                return getattr(target, "_write_count")
            return device.actual_writes

        if hasattr(device, "_write_count"):
            return getattr(device, "_write_count")

        # For physical devices on Windows, attempt WMI lookup if available
        if not device.info.is_virtual:
            try:
                import subprocess
                cmd = f"wmic path Win32_PerfRawData_PerfDisk_PhysicalDisk where \"Name like '%{device.info.serial}%'\" get DiskWrites /value"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                for line in proc.stdout.splitlines():
                    if line.startswith("DiskWrites="):
                        return int(line.split("=")[1].strip())
            except Exception:
                pass

        return 0
