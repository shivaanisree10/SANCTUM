import logging
from typing import Optional
from sanctum.dal import BaseDevice
from sanctum.audit import AuditWriter
from sanctum.exceptions import SanctumError
from sanctum.firmware.models import FirmwareStatus, SanitizeMethod, RiskReport
from sanctum.firmware.adapters import (
    BaseSanitizeAdapter,
    MockAtaAdapter,
    MockNvmeAdapter,
    MockScsiAdapter,
    MockUnsupportedAdapter
)

logger = logging.getLogger("sanctum.firmware.sanitizer")

class FirmwareSanitizationError(SanctumError):
    """Raised when a firmware sanitization check or operation fails."""
    pass

class FirmwareSanitizer:
    """
    Orchestrates Firmware-level sanitization checks and operations.
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    
    def __init__(self, device: BaseDevice, operator_id: str = "SYSTEM", job_id: str = "N/A", audit: Optional[AuditWriter] = None):
        self.device = device
        self.operator_id = operator_id
        self.job_id = job_id
        self.audit = audit
        self.adapter = self._detect_adapter(device)
        logger.warning("Initializing FirmwareSanitizer: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE")

    def _detect_adapter(self, device: BaseDevice) -> BaseSanitizeAdapter:
        """Detects capability and binds the correct adapter mock based on identity."""
        serial = device.info.serial.lower()
        if "nvme" in serial:
            return MockNvmeAdapter()
        elif "scsi" in serial:
            return MockScsiAdapter()
        elif "unsupported" in serial:
            return MockUnsupportedAdapter()
        else:
            # Default to ATA for demonstration
            return MockAtaAdapter()

    def sanitize(self, method: SanitizeMethod) -> bool:
        """
        Executes the firmware sanitization routine.
        WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
        """
        
        # 1. Capability Detection Abstraction
        caps = self.adapter.detect_capabilities()
        if not caps or method not in caps or SanitizeMethod.NONE in caps:
            msg = f"Firmware sanitization method {method.value} is UNAVAILABLE for device {self.device.info.serial}."
            logger.error(msg)
            # Explicitly log the condition and report unavailability. No silent fallback to overwrite.
            if self.audit:
                self.audit.append(
                    operator_id=self.operator_id,
                    job_id=self.job_id,
                    device_serial=self.device.info.serial,
                    operation="FIRMWARE_SANITIZE_CHECK",
                    result="UNAVAILABLE",
                    policy_info={"requested_method": method.value, "capabilities": [c.value for c in caps]}
                )
            raise FirmwareSanitizationError(msg)
            
        # 2. Frozen-drive detection abstraction
        status = self.adapter.detect_frozen()
        if status == FirmwareStatus.FROZEN:
            msg = f"Device {self.device.info.serial} is FROZEN by BIOS/UEFI. Sanitization rejected."
            logger.error(msg)
            raise FirmwareSanitizationError(msg)
            
        # 3. Namespace validation abstraction
        if not self.adapter.validate_namespace():
            raise FirmwareSanitizationError("Namespace validation failed. Risk of collateral data destruction.")
            
        # 4. Power-safety validation abstraction
        if not self.adapter.validate_power_safety():
            raise FirmwareSanitizationError("Power-safety validation failed. Device lacks protection against asynchronous power loss.")

        # 5. Execute Mock Action
        if self.audit:
            self.audit.append(
                operator_id=self.operator_id,
                job_id=self.job_id,
                device_serial=self.device.info.serial,
                operation="FIRMWARE_SANITIZE_START",
                result="STARTED",
                policy_info={"method": method.value, "mock": True}
            )
            
        success = self.adapter.execute(method)
        
        # 6. Residual-risk reporting
        risk_report = self.adapter.get_risk_report()
        logger.info(f"Residual Risk Report: {risk_report.residual_risk_level} - {risk_report.notes}")

        if self.audit:
            self.audit.append(
                operator_id=self.operator_id,
                job_id=self.job_id,
                device_serial=self.device.info.serial,
                operation="FIRMWARE_SANITIZE_END",
                result="SUCCESS" if success else "FAILURE",
                policy_info={"method": method.value, "risk_level": risk_report.residual_risk_level}
            )

        return success
