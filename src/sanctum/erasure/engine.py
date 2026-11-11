import time
import threading
from typing import List, Callable, Optional

from sanctum.dal import BaseDevice
from sanctum.safety import SafetyGuard, CapabilityToken, OperationMode
from sanctum.audit import AuditWriter
from sanctum.erasure.patterns import PatternType, get_pattern_block
from sanctum.erasure.models import ErasureState, ErasureProgress
from sanctum.exceptions import SanctumError
from sanctum.verification.verifier import ErasureVerifier
from sanctum.verification.models import VerificationReport, VerificationResult

class ErasureEngine:
    """Core erasure engine with strict safety guards, auditing, and verification integration."""
    
    def __init__(self, device: BaseDevice, guard: SafetyGuard, token: CapabilityToken, audit: AuditWriter):
        # 1. M2 Safety Integration: Explicitly validate the token before allowing initialization
        guard.validate_token(token, device.info, OperationMode.SANITIZATION)
        
        self.device = device
        self.guard = guard
        self.token = token
        self.audit = audit
        
        self.state = ErasureState.IDLE
        self.errors = 0
        self.read_errors = 0
        self.write_errors = 0
        self.verification_report: Optional[VerificationReport] = None
        
        self._pause_event = threading.Event()
        self._pause_event.set()  # True = running, False = paused
        self._abort_event = threading.Event()

    def reset_state(self) -> None:
        """Reset error counters and execution flags between operation jobs."""
        self.state = ErasureState.IDLE
        self.errors = 0
        self.read_errors = 0
        self.write_errors = 0
        self.verification_report = None
        self._pause_event.set()
        self._abort_event.clear()

    def pause(self) -> None:
        if self.state == ErasureState.RUNNING:
            self.state = ErasureState.PAUSED
            self._pause_event.clear()

    def resume(self) -> None:
        if self.state == ErasureState.PAUSED:
            self.state = ErasureState.RUNNING
            self._pause_event.set()

    def abort(self) -> None:
        self._abort_event.set()
        self._pause_event.set()  # Unblock if currently paused

    def run(
        self,
        policy,
        block_size: int = 1048576,
        callback: Optional[Callable[[ErasureProgress], None]] = None,
        sample_percentage: float = 100.0,
    ) -> ErasureState:
        """
        Execute the erasure passes with sector/block level processing according to policy.
        If policy requires verification and overwrite completes without abort/error,
        automatically triggers the VerificationEngine.
        """
        # If abort was called before run(), preserve abort signal
        was_aborted = self._abort_event.is_set()
        self.reset_state()
        if was_aborted:
            self._abort_event.set()

        self.state = ErasureState.RUNNING
        
        passes = policy.passes
        if not passes:
            self.state = ErasureState.ERROR
            self.errors += 1
            return self.state
        
        # 2. M3 Audit Integration: Log start of destructive operation
        self.audit.append(
            operator_id="OP",
            job_id=self.token.job_id,
            device_serial=self.device.info.serial,
            operation="ERASE_START",
            result="STARTED",
            policy_info={"policy_name": policy.name, "passes": [p.value for p in passes], "block_size": block_size}
        )

        total_bytes = self.device.info.capacity_bytes * len(passes)
        bytes_processed = 0
        start_time = time.time()
        
        sector_size = self.device.info.sector_size
        sectors_per_block = max(1, block_size // sector_size)
        total_sectors = self.device.info.lba_count
        
        for pass_idx, pattern in enumerate(passes, 1):
            if self._abort_event.is_set():
                break
                
            for lba in range(0, total_sectors, sectors_per_block):
                # Handle Pausing
                self._pause_event.wait()
                if self._abort_event.is_set():
                    break
                    
                sectors_to_write = min(sectors_per_block, total_sectors - lba)
                # Generate pattern per block independently (especially for RANDOM)
                block_data = get_pattern_block(pattern, sectors_to_write * sector_size)
                
                try:
                    # Sector-based execution fallback loop (to accommodate DAL strictly)
                    for i in range(sectors_to_write):
                        self.device.write_sector(lba + i, block_data[i*sector_size:(i+1)*sector_size])
                    bytes_processed += (sectors_to_write * sector_size)
                except Exception as e:
                    self.errors += 1
                    self.write_errors += 1
                
                # Progress Reporting
                if callback:
                    elapsed = time.time() - start_time
                    throughput = bytes_processed / elapsed if elapsed > 0 else 0
                    prog = ErasureProgress(
                        percentage=(bytes_processed / total_bytes) * 100 if total_bytes > 0 else 100,
                        current_pass=pass_idx,
                        total_passes=len(passes),
                        bytes_processed=bytes_processed,
                        total_bytes=total_bytes,
                        throughput_bytes_per_sec=throughput,
                        state=self.state,
                        errors=self.errors
                    )
                    callback(prog)
                    
            # Flush at the end of each pass safely
            try:
                if hasattr(self.device, "flush"):
                    self.device.flush()
            except Exception as e:
                self.errors += 1
                self.write_errors += 1

        # Determine intermediate state after overwrite passes
        if self._abort_event.is_set():
            self.state = ErasureState.ABORTED
            final_result = "ABORTED"
        elif self.errors > 0:
            self.state = ErasureState.ERROR
            final_result = "ERROR"
        else:
            self.state = ErasureState.COMPLETED
            final_result = "SUCCESS"

        # 3. Verification Trigger: If overwrite succeeded and policy requires verification
        verif_val = policy.verification.value if hasattr(policy.verification, "value") else str(policy.verification)
        if self.state == ErasureState.COMPLETED and verif_val != "NONE":
            verifier = ErasureVerifier(self.device, self.audit, self.token.job_id)
            report = verifier.verify(policy, sample_percentage=sample_percentage)
            self.verification_report = report
            if report.result != VerificationResult.PASS:
                # Verification failed or quarantined -> overall state fails closed
                self.state = ErasureState.ERROR
                self.errors += (report.defects + (1 if report.result == VerificationResult.FAIL else 0))
                final_result = f"VERIFICATION_{report.result.value}"

        # 4. M3 Audit Integration: Log end result
        self.audit.append(
            operator_id="OP",
            job_id=self.token.job_id,
            device_serial=self.device.info.serial,
            operation="ERASE_END",
            result=final_result,
            policy_info={
                "errors": self.errors,
                "write_errors": self.write_errors,
                "read_errors": self.read_errors,
                "bytes_processed": bytes_processed,
                "verification_result": self.verification_report.result.value if self.verification_report else "NONE",
                "disposition": self.verification_report.disposition if self.verification_report else "UNVERIFIED"
            }
        )

        return self.state
