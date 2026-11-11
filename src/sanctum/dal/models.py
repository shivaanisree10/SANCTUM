from pydantic import BaseModel

class DeviceInfo(BaseModel):
    """Data model representing a storage device's geometry and identity."""
    path: str
    serial: str
    capacity_bytes: int
    sector_size: int = 512
    lba_count: int
    is_virtual: bool
