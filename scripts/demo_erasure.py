import time
from pathlib import Path
from sanctum.dal import VirtualDevice
from sanctum.safety import SafetyGuard, OperationMode
from sanctum.audit import AuditWriter
from sanctum.erasure import ErasureEngine, PatternType, ErasureProgress

def main():
    img_path = Path("test_lab/media.img")
    audit_path = Path("test_lab/audit.log")
    
    print(f"--- SANCTUM OVERWRITE DEMO ---")
    print(f"Target: {img_path}")
    
    device = VirtualDevice(img_path)
    guard = SafetyGuard()
    # Acquire token safely
    token = guard.request_token(device.info, "DEMO-JOB", "OP-ERASE", OperationMode.SANITIZATION, confirmed=True)
    audit = AuditWriter(str(audit_path))
    
    from sanctum.policies import PolicyRegistry
    registry = PolicyRegistry()
    registry.load_file("config/default_policies.yaml")
    policy = registry.get_policy("DoD-3pass")
    
    print(registry.explain_policy(policy))
    
    engine = ErasureEngine(device, guard, token, audit)
    
    def on_progress(p: ErasureProgress):
        print(f"\rPass {p.current_pass}/{p.total_passes} | {p.percentage:.1f}% | {p.throughput_bytes_per_sec/1024/1024:.2f} MB/s", end="")
    
    print(f"\nStarting {policy.name}...")
    start = time.time()
    
    # Run the erasure engine using the selected policy
    engine.run(policy, block_size=1024*1024, callback=on_progress)
    
    print(f"\nCompleted in {time.time() - start:.2f} seconds.")
    print(f"Final State: {engine.state.value}")
    
    device.close()

if __name__ == "__main__":
    main()
