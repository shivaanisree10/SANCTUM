import pytest
import json
import os
from pathlib import Path
from sanctum.audit import AuditWriter, verify_audit_log, TamperType

@pytest.fixture
def audit_log(tmp_path: Path) -> Path:
    log_path = tmp_path / "audit.log"
    writer = AuditWriter(str(log_path))
    # Write 3 valid entries
    writer.append("OP1", "JOB1", "SERIAL1", "ACQUISITION", "SUCCESS", {"pol": 1})
    writer.append("OP1", "JOB2", "SERIAL2", "SANITIZATION", "SUCCESS", {"pol": 1})
    writer.append("OP2", "JOB3", "SERIAL1", "ASSURANCE", "FAILURE", {"pol": 2})
    return log_path

def test_audit_valid(audit_log: Path) -> None:
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is True
    assert tamper_type == TamperType.NONE

def test_audit_modified_entry(audit_log: Path) -> None:
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    # Modify the second entry (index 1)
    data = json.loads(lines[1])
    data["result"] = "FAILURE" # Tampering
    lines[1] = json.dumps(data)
    
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is False
    assert tamper_type == TamperType.MODIFIED
    assert "Content was modified" in msg

def test_audit_deleted_entry(audit_log: Path) -> None:
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    # Delete the second entry (index 1)
    del lines[1]
    
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is False
    assert tamper_type == TamperType.DELETED
    assert "Sequence jump" in msg

def test_audit_reordered_entries(audit_log: Path) -> None:
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    # Swap index 1 and 2
    lines[1], lines[2] = lines[2], lines[1]
    
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is False
    assert tamper_type in (TamperType.REORDERED, TamperType.DELETED)

def test_audit_truncated_entry(audit_log: Path) -> None:
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    # Truncate the last entry (cut off half the JSON)
    lines[-1] = lines[-1][:len(lines[-1]) // 2]
    
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is False
    assert tamper_type == TamperType.TRUNCATED
    assert "malformed" in msg

def test_audit_broken_chain(audit_log: Path) -> None:
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    # Break the hash chain manually
    data = json.loads(lines[2])
    data["previous_hash"] = "0" * 64
    # Fix the self-hash so MODIFIED doesn't trigger first
    # We want to trigger REORDERED/Chain Broken
    import hashlib
    data_to_hash = {
        "seq": data["sequence_number"],
        "ts": data["timestamp"],
        "op_id": data["operator_id"],
        "job": data["job_id"],
        "dev": data["device_serial"],
        "op": data["operation"],
        "res": data["result"],
        "pol": data["policy_info"],
        "prev": data["previous_hash"]
    }
    serialized = json.dumps(data_to_hash, sort_keys=True, separators=(',', ':'))
    data["entry_hash"] = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    
    lines[2] = json.dumps(data)
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    is_valid, tamper_type, msg = verify_audit_log(str(audit_log))
    assert is_valid is False
    assert tamper_type == TamperType.REORDERED
    assert "Hash chain broken" in msg
