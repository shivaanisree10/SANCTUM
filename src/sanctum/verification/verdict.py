from typing import List, Optional
from sanctum.verification.models import VerificationResult

class VerdictEngine:
    """Evaluates verification evidence to produce a strict PASS/FAIL/QUARANTINE verdict."""
    
    def __init__(self):
        self.block_mismatches = 0
        self.write_defects = 0
        self.read_defects = 0
        self.recovery_artefacts = 0
        self.reasons: List[str] = []

    def report_mismatch(self, lba: int, expected: bytes, actual: bytes) -> None:
        self.block_mismatches += 1
        self.reasons.append(f"Block mismatch at LBA {lba}.")

    def report_write_defect(self, lba: int, error: str) -> None:
        self.write_defects += 1
        self.reasons.append(f"Write defect at LBA {lba}: {error}")

    def report_read_defect(self, lba: int, error: str) -> None:
        self.read_defects += 1
        self.reasons.append(f"Read defect at LBA {lba}: {error}")

    def report_random_unverifiable(self, lba: int) -> None:
        self.read_defects += 1
        self.reasons.append(f"Unverifiable random pattern at LBA {lba}: random bytes cannot be verified without deterministic PRNG seed ledger.")

    def report_recovery_artefact(self, description: str) -> None:
        self.recovery_artefacts += 1
        self.reasons.append(f"Recovery artefact detected: {description}")

    def evaluate(self) -> VerificationResult:
        if self.recovery_artefacts > 0:
            return VerificationResult.FAIL
        
        if self.block_mismatches > 0:
            return VerificationResult.FAIL
            
        if self.write_defects > 0 or self.read_defects > 0:
            # Policy invalidation due to defects causing incomplete wipe/verification
            self.reasons.append("Quarantine recommendation: Defective sectors or unverifiable blocks may harbor residual data.")
            return VerificationResult.QUARANTINE
            
        return VerificationResult.PASS

    def get_errors_string(self) -> str:
        return " | ".join(self.reasons)
