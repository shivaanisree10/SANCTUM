import pytest
from pathlib import Path
from sanctum.policies import PolicyRegistry, PolicyError, ErasurePolicy
from sanctum.dal import DeviceInfo

@pytest.fixture
def registry(tmp_path: Path) -> PolicyRegistry:
    # Write a quick temporary yaml just for testing the registry loading natively
    yaml_content = """
policies:
  - name: "TEST-Clear"
    description: "test"
    reference: "test"
    category: "test"
    passes: ["ZERO"]
    verification: "NONE"
    applicable_media: ["VIRTUAL"]
    version: "1.0"
  - name: "TEST-Magnetic"
    description: "test mag"
    reference: "test"
    category: "test"
    passes: ["RANDOM"]
    verification: "NONE"
    applicable_media: ["MAGNETIC"]
    version: "1.0"
"""
    p = tmp_path / "test.yaml"
    p.write_text(yaml_content)
    
    reg = PolicyRegistry()
    reg.load_file(p)
    return reg

def test_registry_load_and_get(registry: PolicyRegistry):
    p = registry.get_policy("TEST-Clear")
    assert p.name == "TEST-Clear"
    assert len(p.passes) == 1
    
    with pytest.raises(PolicyError):
        registry.get_policy("NON-EXISTENT")

def test_registry_validation(registry: PolicyRegistry):
    pol_virtual = registry.get_policy("TEST-Clear")
    pol_magnetic = registry.get_policy("TEST-Magnetic")
    
    dev_virtual = DeviceInfo(path="v", serial="1", capacity_bytes=100, lba_count=1, is_virtual=True)
    dev_physical = DeviceInfo(path="p", serial="2", capacity_bytes=100, lba_count=1, is_virtual=False)
    
    # Virtual device should be allowed for TEST-Clear
    assert registry.validate_policy_for_device(pol_virtual, dev_virtual)
    
    # Virtual device should NOT be allowed for TEST-Magnetic
    with pytest.raises(PolicyError, match="not applicable to media class VIRTUAL"):
        registry.validate_policy_for_device(pol_magnetic, dev_virtual)
        
    # Physical device should NOT be allowed for TEST-Clear
    with pytest.raises(PolicyError, match="not applicable to media class MAGNETIC"):
        registry.validate_policy_for_device(pol_virtual, dev_physical)

def test_estimation(registry: PolicyRegistry):
    pol = registry.get_policy("TEST-Clear")
    dev = DeviceInfo(path="v", serial="1", capacity_bytes=104857600, lba_count=1, is_virtual=True) # 100MB
    # 100MB at 100MB/s = 1.0 second
    est = registry.estimate_time(pol, dev, write_speed_mbps=100.0)
    assert est == 1.0
