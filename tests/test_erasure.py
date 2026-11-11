import pytest
import os
import threading
import time
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.safety import SafetyGuard, OperationMode
from sanctum.audit import AuditWriter
from sanctum.erasure import ErasureEngine, PatternType, ErasureState, ErasureProgress

def create_dummy_data(path: Path, size_bytes: int) -> None:
    with open(path, "wb") as f:
        f.write(b"A" * size_bytes)

def test_erasure_engine_execution(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    audit_path = tmp_path / "audit.log"
    size = 4096 # 8 sectors
    create_dummy_data(img_path, size)
    
    device = VirtualDevice(img_path)
    guard = SafetyGuard()
    token = guard.request_token(device.info, "JOB1", "OP1", OperationMode.SANITIZATION, confirmed=True)
    audit = AuditWriter(str(audit_path))
    
    engine = ErasureEngine(device, guard, token, audit)
    
    progress_updates = []
    def on_progress(p: ErasureProgress):
        progress_updates.append(p.percentage)
        
    from sanctum.policies import ErasurePolicy, MediaClass, VerificationRequirement
    policy = ErasurePolicy(
        name="TEST-Policy",
        description="test",
        reference="none",
        category="test",
        passes=[PatternType.ONES, PatternType.ZERO],
        verification=VerificationRequirement.NONE,
        applicable_media=[MediaClass.ANY],
        version="1.0"
    )
    
    state = engine.run(policy, block_size=1024, callback=on_progress)
    
    assert state == ErasureState.COMPLETED
    assert engine.errors == 0
    assert len(progress_updates) > 0
    assert progress_updates[-1] == 100.0
    
    # Verification
    device.close()
    with open(img_path, "rb") as f:
        data = f.read()
        assert data == b"\x00" * size
        
    # Check Audit log
    audit_content = audit_path.read_text(encoding="utf-8")
    assert "ERASE_START" in audit_content
    assert "ERASE_END" in audit_content
    assert "SUCCESS" in audit_content

def test_erasure_engine_pause_abort(tmp_path: Path) -> None:
    img_path = tmp_path / "test.img"
    audit_path = tmp_path / "audit.log"
    size = 1024 * 1024 # 1MB to give time to pause
    create_dummy_data(img_path, size)
    
    device = VirtualDevice(img_path)
    guard = SafetyGuard()
    token = guard.request_token(device.info, "JOB2", "OP2", OperationMode.SANITIZATION, confirmed=True)
    audit = AuditWriter(str(audit_path))
    
    engine = ErasureEngine(device, guard, token, audit)
    
    def delayed_abort():
        time.sleep(0.001)
        engine.pause()
        time.sleep(0.005)
        engine.abort()
        
    t = threading.Thread(target=delayed_abort)
    t.start()
    
    from sanctum.policies import ErasurePolicy, MediaClass, VerificationRequirement
    policy = ErasurePolicy(
        name="TEST-Pause",
        description="test",
        reference="none",
        category="test",
        passes=[PatternType.ZERO],
        verification=VerificationRequirement.NONE,
        applicable_media=[MediaClass.ANY],
        version="1.0"
    )
    
    state = engine.run(policy, block_size=1024)
    t.join()
    
    assert state == ErasureState.ABORTED
    device.close()
