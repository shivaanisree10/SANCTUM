import json
import os
from enum import Enum
from typing import Tuple
from sanctum.audit.models import AuditEntry

class TamperType(Enum):
    NONE = "NONE"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    REORDERED = "REORDERED"
    TRUNCATED = "TRUNCATED"
    CORRUPTED = "CORRUPTED"

def verify_audit_log(log_path: str) -> Tuple[bool, TamperType, str]:
    """Verify the cryptographic integrity and sequence of the audit log."""
    if not os.path.exists(log_path):
        return False, TamperType.CORRUPTED, "Audit log does not exist."

    expected_seq = 0
    expected_prev_hash = "0" * 64

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                entry = AuditEntry(**data)
            except json.JSONDecodeError:
                return False, TamperType.TRUNCATED, f"Line {line_num} is malformed/truncated JSON."
            except Exception as e:
                return False, TamperType.CORRUPTED, f"Line {line_num} has missing fields: {e}"

            # Check sequence continuity
            if entry.sequence_number != expected_seq:
                if entry.sequence_number > expected_seq:
                    return False, TamperType.DELETED, f"Sequence jump at line {line_num}. Expected {expected_seq}, got {entry.sequence_number}."
                else:
                    return False, TamperType.REORDERED, f"Sequence drop at line {line_num}. Expected {expected_seq}, got {entry.sequence_number}."

            # Check previous hash binding (chain)
            if entry.previous_hash != expected_prev_hash:
                return False, TamperType.REORDERED, f"Hash chain broken at line {line_num}. Expected prev_hash {expected_prev_hash}, got {entry.previous_hash}."

            # Check data modification
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                return False, TamperType.MODIFIED, f"Entry hash mismatch at line {line_num}. Content was modified."

            # Advance expected state
            expected_seq += 1
            expected_prev_hash = entry.entry_hash

    if expected_seq == 0:
        return False, TamperType.CORRUPTED, "Audit log is empty."

    return True, TamperType.NONE, "Audit log is structurally intact."
