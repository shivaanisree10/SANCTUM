import yaml
from pathlib import Path
from typing import Dict, List
from sanctum.policies.models import ErasurePolicy, MediaClass
from sanctum.dal import DeviceInfo
from sanctum.exceptions import SanctumError

class PolicyError(SanctumError):
    pass

class PolicyRegistry:
    def __init__(self) -> None:
        self._policies: Dict[str, ErasurePolicy] = {}

    def load_directory(self, path: Path | str) -> None:
        p = Path(path)
        if not p.exists() or not p.is_dir():
            return
        for file_path in p.glob("*.yaml"):
            self.load_file(file_path)

    def load_file(self, path: Path | str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise PolicyError(f"Invalid YAML syntax in {path}: {e}")
                
        if not data or "policies" not in data:
            return
            
        for pol_data in data["policies"]:
            try:
                pol = ErasurePolicy(**pol_data)
                self._policies[pol.name] = pol
            except Exception as e:
                raise PolicyError(f"Invalid policy schema in {path}: {e}")

    def get_policy(self, name: str) -> ErasurePolicy:
        if name not in self._policies:
            raise PolicyError(f"Policy '{name}' not found in registry.")
        return self._policies[name]
        
    def list_policies(self) -> List[ErasurePolicy]:
        return list(self._policies.values())

    def validate_policy_for_device(self, policy: ErasurePolicy, device: DeviceInfo) -> bool:
        dev_class = MediaClass.VIRTUAL if device.is_virtual else MediaClass.MAGNETIC
        if MediaClass.ANY in policy.applicable_media:
            return True
        if dev_class not in policy.applicable_media:
            msg = f"Policy {policy.name} is not applicable to media class {dev_class.value}."
            if policy.advisory:
                msg += f" Advisory: {policy.advisory}"
            raise PolicyError(msg)
        return True

    def estimate_time(self, policy: ErasurePolicy, device: DeviceInfo, write_speed_mbps: float = 100.0) -> float:
        """Returns estimated execution time in seconds."""
        total_bytes = device.capacity_bytes * len(policy.passes)
        if write_speed_mbps <= 0:
            return 0.0
        return (total_bytes / (1024 * 1024)) / write_speed_mbps
        
    def explain_policy(self, policy: ErasurePolicy) -> str:
        adv = policy.advisory if policy.advisory else "None"
        passes_list = [p.value for p in policy.passes]
        return (f"Policy: {policy.name} (v{policy.version})\n"
                f"Ref: {policy.reference}\n"
                f"Desc: {policy.description}\n"
                f"Category: {policy.category}\n"
                f"Passes ({len(policy.passes)}): {passes_list}\n"
                f"Verification: {policy.verification.value}\n"
                f"Applicable Media: {[m.value for m in policy.applicable_media]}\n"
                f"Advisory: {adv}")
