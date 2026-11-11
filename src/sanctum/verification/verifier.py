import hashlib
import datetime
import uuid
from typing import Tuple, List, TYPE_CHECKING

from sanctum.dal import BaseDevice
from sanctum.audit import AuditWriter
from sanctum.erasure.patterns import PatternType, get_pattern_block
from sanctum.verification.models import VerificationReport, VerificationResult
from sanctum.verification.verdict import VerdictEngine
from sanctum.verification.sampling import VerificationSampler
from sanctum.verification.adversarial import MockAdversarialScanner

if TYPE_CHECKING:
    from sanctum.policies.models import ErasurePolicy

class ErasureVerifier:
    def __init__(self, device: BaseDevice, audit: AuditWriter, job_id: str):
        self.device = device
        self.audit = audit
        self.job_id = job_id
        self.adversarial_scanner = MockAdversarialScanner()

    def verify(self, policy: ErasurePolicy, sample_percentage: float = 100.0) -> VerificationReport:
        self.audit.append(
            operator_id="SYSTEM",
            job_id=self.job_id,
            device_serial=self.device.info.serial,
            operation="VERIFICATION_START",
            result="STARTED",
            policy_info={"policy_name": policy.name, "coverage": sample_percentage}
        )

        verif_str = policy.verification.value if hasattr(policy.verification, "value") else str(policy.verification)
        verdict_engine = VerdictEngine()
        dev_hash = "N/A"
        
        # Policy & Geometry Pre-validation
        if not policy.passes:
            verdict_engine.reasons.append("Invalid policy: Policy specifies zero overwrite passes.")
            verdict_engine.write_defects += 1
            final_result = verdict_engine.evaluate()
        elif verif_str == "ALL_PASSES":
            # ALL_PASSES cannot be genuinely verified post-facto because earlier passes were overwritten by subsequent passes
            verdict_engine.reasons.append("Verification requirement ALL_PASSES is unsupported for post-erasure read-back: intermediate passes have been overwritten.")
            verdict_engine.write_defects += 1
            final_result = verdict_engine.evaluate()
        elif verif_str == "NONE":
            final_result = VerificationResult.SKIPPED
            verdict_engine.reasons.append("Verification skipped by policy.")
        else:
            expected_pattern = policy.passes[-1]
            hasher = hashlib.sha256()
            
            total_sectors = self.device.info.lba_count
            sampler = VerificationSampler(total_sectors, seed=self.job_id)
            
            # Determine which LBAs to verify
            if sample_percentage >= 100.0:
                lbas_to_check = list(sampler.get_full_coverage())
            else:
                mandatory = set(sampler.get_mandatory_regions())
                random_sample = set(sampler.get_random_sample(sample_percentage))
                lbas_to_check = sorted(list(mandatory.union(random_sample)))
            
            # Defensive check: Verification must NEVER report PASS when zero sectors were checked!
            if len(lbas_to_check) == 0:
                verdict_engine.reasons.append("Zero sectors selected or available for verification check.")
                verdict_engine.write_defects += 1

            # Expected block regeneration
            expected_block = get_pattern_block(expected_pattern, self.device.info.sector_size) if expected_pattern != PatternType.RANDOM else None
            
            # Rolling SHA-256 and read-back verification
            for lba in lbas_to_check:
                try:
                    data = self.device.read_sector(lba)
                    hasher.update(data)
                    
                    if expected_block is not None:
                        if data != expected_block:
                            verdict_engine.report_mismatch(lba, expected_block, data)
                    elif expected_pattern == PatternType.RANDOM:
                        # RANDOM overwrite verification cannot report PASS without a reliable expected-data comparison
                        verdict_engine.report_random_unverifiable(lba)
                            
                except Exception as e:
                    verdict_engine.report_read_defect(lba, str(e))
            
            # Adversarial scanning for recovery artefacts
            artefacts = self.adversarial_scanner.scan_for_artefacts(self.device)
            for a in artefacts:
                verdict_engine.report_recovery_artefact(a)
                
            dev_hash = hasher.hexdigest()
            # Partial verification must not be presented as a complete device hash
            if sample_percentage < 100.0:
                dev_hash = f"PARTIAL-SAMPLE-HASH({sample_percentage}%):{dev_hash}"
            final_result = verdict_engine.evaluate()

        report = VerificationReport(
            certificate_id=f"CERT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            tool_version="1.0.0",
            policy_name=policy.name,
            policy_version=policy.version,
            device_identity=self.device.info.path,
            device_serial=self.device.info.serial,
            device_wwn="WWN-NOT-PROVIDED",
            capacity_bytes=self.device.info.capacity_bytes,
            method="OVERWRITE",
            passes_completed=len(policy.passes),
            verification_method="FULL" if sample_percentage >= 100.0 else "STATISTICAL_SAMPLE",
            coverage=f"{sample_percentage}%",
            result=final_result,
            device_hash_sha256=dev_hash,
            defects=verdict_engine.write_defects,
            operator="SYSTEM",
            work_order=self.job_id,
            disposition="SANITIZED" if final_result == VerificationResult.PASS else "QUARANTINED",
            residual_risk="NONE" if final_result == VerificationResult.PASS else "HIGH",
            audit_digest="PENDING", # Finalized later
            errors=verdict_engine.get_errors_string(),
            audit_job_id=self.job_id
        )

        self.audit.append(
            operator_id="SYSTEM",
            job_id=self.job_id,
            device_serial=self.device.info.serial,
            operation="VERIFICATION_END",
            result=final_result.value,
            policy_info={"hash": dev_hash, "errors": report.errors, "cert_id": report.certificate_id}
        )

        return report
