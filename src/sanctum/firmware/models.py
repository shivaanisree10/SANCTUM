from enum import Enum
from pydantic import BaseModel

class FirmwareStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    FROZEN = "FROZEN"
    LOCKED = "LOCKED"
    UNSUPPORTED = "UNSUPPORTED"

class SanitizeMethod(str, Enum):
    BLOCK_ERASE = "BLOCK_ERASE"
    CRYPTO_ERASE = "CRYPTO_ERASE"
    OVERWRITE = "OVERWRITE"
    NONE = "NONE"

class RiskReport(BaseModel):
    residual_risk_level: str
    reallocated_sectors_cleared: bool
    hidden_areas_cleared: bool
    notes: str
