from enum import Enum
from pydantic import BaseModel

class ErasureState(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    ABORTED = "ABORTED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"

class ErasureProgress(BaseModel):
    percentage: float
    current_pass: int
    total_passes: int
    bytes_processed: int
    total_bytes: int
    throughput_bytes_per_sec: float
    state: ErasureState
    errors: int
