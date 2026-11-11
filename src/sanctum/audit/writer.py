import json
import os
import datetime
import threading
from typing import Dict, Any
from sanctum.audit.models import AuditEntry
from sanctum.exceptions import SanctumError

class AuditError(SanctumError):
    pass

class AuditWriter:
    """Thread-safe append-only audit log writer."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._last_seq = -1
        self._last_hash = "0" * 64
        self._init_chain()

    def _init_chain(self) -> None:
        """Initialize the genesis entry or recover state from the last valid entry."""
        with self._lock:
            if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
                self._write_genesis_unlocked()
            else:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    lines = [line for line in f if line.strip()]
                    if not lines:
                        self._write_genesis_unlocked()
                    else:
                        last_line = lines[-1]
                        try:
                            data = json.loads(last_line)
                            self._last_seq = data["sequence_number"]
                            self._last_hash = data["entry_hash"]
                        except (json.JSONDecodeError, KeyError) as e:
                            raise AuditError(f"Audit log is corrupted and cannot be initialized: {e}")

    def _write_genesis_unlocked(self) -> None:
        """Writes the initial record to anchor the hash chain."""
        self._last_seq = 0
        self._last_hash = "0" * 64
        entry = AuditEntry(
            sequence_number=0,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            operator_id="SYSTEM",
            job_id="GENESIS",
            device_serial="N/A",
            operation="INIT",
            result="SUCCESS",
            policy_info={"version": "1.0"},
            previous_hash=self._last_hash
        )
        entry.entry_hash = entry.compute_hash()
        
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")
            
        self._last_seq = entry.sequence_number
        self._last_hash = entry.entry_hash

    def append(self, operator_id: str, job_id: str, device_serial: str, operation: str, result: str, policy_info: Dict[str, Any]) -> None:
        """Append a new record securely to the chain."""
        with self._lock:
            entry = AuditEntry(
                sequence_number=self._last_seq + 1,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                operator_id=operator_id,
                job_id=job_id,
                device_serial=device_serial,
                operation=operation,
                result=result,
                policy_info=policy_info,
                previous_hash=self._last_hash
            )
            entry.entry_hash = entry.compute_hash()

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
                
            self._last_seq = entry.sequence_number
            self._last_hash = entry.entry_hash
