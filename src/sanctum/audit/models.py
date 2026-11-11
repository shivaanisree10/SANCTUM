import hashlib
import json
from pydantic import BaseModel
from typing import Dict, Any

class AuditEntry(BaseModel):
    """Structured audit entry for M3 tamper-evident log."""
    sequence_number: int
    timestamp: str
    operator_id: str
    job_id: str
    device_serial: str
    operation: str
    result: str
    policy_info: Dict[str, Any]
    previous_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the entry's canonical JSON representation."""
        data = {
            "seq": self.sequence_number,
            "ts": self.timestamp,
            "op_id": self.operator_id,
            "job": self.job_id,
            "dev": self.device_serial,
            "op": self.operation,
            "res": self.result,
            "pol": self.policy_info,
            "prev": self.previous_hash
        }
        # Serialize deterministically (sorted keys, no spaces)
        serialized = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()
