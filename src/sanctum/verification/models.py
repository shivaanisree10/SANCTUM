from pydantic import BaseModel
from enum import Enum

class VerificationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    QUARANTINE = "QUARANTINE"
    SKIPPED = "SKIPPED"

class VerificationReport(BaseModel):
    certificate_id: str
    timestamp: str
    tool_version: str
    policy_name: str
    policy_version: str
    device_identity: str
    device_serial: str
    device_wwn: str
    capacity_bytes: int
    method: str
    passes_completed: int
    verification_method: str
    coverage: str
    result: VerificationResult
    device_hash_sha256: str
    defects: int
    operator: str
    work_order: str
    disposition: str
    residual_risk: str
    audit_digest: str
    signature: str = ""
    errors: str
    audit_job_id: str

