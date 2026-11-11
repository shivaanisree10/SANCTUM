import logging
import subprocess
from pathlib import Path
from typing import List, Dict

from sanctum.dal.models import DeviceInfo
from sanctum.dal.device import VirtualDevice

logger = logging.getLogger("sanctum.dal.enumerator")

def enumerate_virtual_devices(test_media_path: str) -> List[DeviceInfo]:
    """Safely enumerate the configured virtual test device."""
    devices = []
    path = Path(test_media_path)
    if path.exists():
        try:
            vd = VirtualDevice(str(path))
            devices.append(vd.info)
            vd.close()
        except Exception as e:
            logger.error(f"Failed to enumerate virtual device {path}: {e}")
    else:
        logger.debug(f"Virtual test media not found at {path}")
    return devices

def _parse_wmic_output(output: str) -> List[Dict[str, str]]:
    """Helper to parse wmic list format into dictionaries."""
    results = []
    current_device = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current_device:
                results.append(current_device)
                current_device = {}
            continue
        
        if "=" in line:
            key, val = line.split("=", 1)
            current_device[key.strip()] = val.strip()
            
    if current_device:
        results.append(current_device)
        
    return results

def enumerate_physical_devices() -> List[DeviceInfo]:
    """Safely enumerate physical drives using wmic (read-only enumeration)."""
    devices = []
    try:
        # Run wmic to get disk drives on Windows
        result = subprocess.run(
            ["wmic", "diskdrive", "get", "DeviceID,SerialNumber,Size,BytesPerSector", "/format:list"],
            capture_output=True, text=True, check=True
        )
        parsed_data = _parse_wmic_output(result.stdout)
        
        for item in parsed_data:
            device_id = item.get("DeviceID")
            serial = item.get("SerialNumber", "UNKNOWN")
            
            try:
                size = int(item.get("Size", 0))
                sector_size = int(item.get("BytesPerSector", 512))
            except ValueError:
                continue
                
            if not device_id or size == 0:
                continue
                
            lba_count = size // sector_size
            
            info = DeviceInfo(
                path=device_id,
                serial=serial,
                capacity_bytes=size,
                sector_size=sector_size,
                lba_count=lba_count,
                is_virtual=False
            )
            devices.append(info)
            
    except subprocess.SubprocessError as e:
        logger.error(f"Physical device enumeration subprocess failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during physical enumeration: {e}")
        
    return devices

def get_all_devices(simulation_mode: bool, test_media_path: str) -> List[DeviceInfo]:
    """Get all applicable devices based on the operation mode."""
    if simulation_mode:
        return enumerate_virtual_devices(test_media_path)
    else:
        # In real hardware mode, we might want to return both physical and virtual (if available).
        # For safety and strict separation, we will return only physical drives.
        return enumerate_physical_devices()
