import abc
import logging
from typing import List
from sanctum.firmware.models import FirmwareStatus, SanitizeMethod, RiskReport

logger = logging.getLogger("sanctum.firmware.adapters")

class BaseSanitizeAdapter(abc.ABC):
    """
    Base Interface for Firmware Sanitization.
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    
    @abc.abstractmethod
    def detect_capabilities(self) -> List[SanitizeMethod]:
        pass

    @abc.abstractmethod
    def detect_frozen(self) -> FirmwareStatus:
        pass

    @abc.abstractmethod
    def validate_namespace(self) -> bool:
        pass

    @abc.abstractmethod
    def validate_power_safety(self) -> bool:
        pass

    @abc.abstractmethod
    def execute(self, method: SanitizeMethod) -> bool:
        pass
        
    @abc.abstractmethod
    def get_risk_report(self) -> RiskReport:
        pass


class MockAtaAdapter(BaseSanitizeAdapter):
    """
    ATA Sanitizer Adapter Interface
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    def detect_capabilities(self) -> List[SanitizeMethod]:
        return [SanitizeMethod.BLOCK_ERASE, SanitizeMethod.CRYPTO_ERASE]

    def detect_frozen(self) -> FirmwareStatus:
        # Simulate an unfrozen drive by default
        return FirmwareStatus.AVAILABLE

    def validate_namespace(self) -> bool:
        return True

    def validate_power_safety(self) -> bool:
        return True

    def execute(self, method: SanitizeMethod) -> bool:
        logger.info(f"[MOCK ATA] Executing firmware command: {method.value}")
        return True
        
    def get_risk_report(self) -> RiskReport:
        return RiskReport(
            residual_risk_level="LOW",
            reallocated_sectors_cleared=True,
            hidden_areas_cleared=True,
            notes="ATA Secure Erase usually clears DCO and HPA."
        )


class MockNvmeAdapter(BaseSanitizeAdapter):
    """
    NVMe Sanitizer Adapter Interface
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    def detect_capabilities(self) -> List[SanitizeMethod]:
        return [SanitizeMethod.CRYPTO_ERASE]

    def detect_frozen(self) -> FirmwareStatus:
        return FirmwareStatus.AVAILABLE

    def validate_namespace(self) -> bool:
        logger.info("[MOCK NVME] Validating namespace boundaries...")
        return True

    def validate_power_safety(self) -> bool:
        logger.info("[MOCK NVME] Validating power loss protection...")
        return True

    def execute(self, method: SanitizeMethod) -> bool:
        logger.info(f"[MOCK NVME] Executing Format NVM command: {method.value}")
        return True
        
    def get_risk_report(self) -> RiskReport:
        return RiskReport(
            residual_risk_level="LOW",
            reallocated_sectors_cleared=True,
            hidden_areas_cleared=True,
            notes="NVMe Format clears all namespaces."
        )


class MockScsiAdapter(BaseSanitizeAdapter):
    """
    SCSI Sanitizer Adapter Interface
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    def detect_capabilities(self) -> List[SanitizeMethod]:
        return [SanitizeMethod.BLOCK_ERASE]

    def detect_frozen(self) -> FirmwareStatus:
        return FirmwareStatus.AVAILABLE

    def validate_namespace(self) -> bool:
        return True

    def validate_power_safety(self) -> bool:
        return True

    def execute(self, method: SanitizeMethod) -> bool:
        logger.info(f"[MOCK SCSI] Executing Format Unit command: {method.value}")
        return True
        
    def get_risk_report(self) -> RiskReport:
        return RiskReport(
            residual_risk_level="MEDIUM",
            reallocated_sectors_cleared=False,
            hidden_areas_cleared=True,
            notes="SCSI Format Unit may skip grown defect list."
        )

class MockUnsupportedAdapter(BaseSanitizeAdapter):
    """
    Adapter for drives lacking firmware sanitization features.
    WARNING: DEMO / MOCK / NOT ENABLED FOR REAL HARDWARE
    """
    def detect_capabilities(self) -> List[SanitizeMethod]:
        return [SanitizeMethod.NONE]

    def detect_frozen(self) -> FirmwareStatus:
        return FirmwareStatus.UNSUPPORTED

    def validate_namespace(self) -> bool:
        return False

    def validate_power_safety(self) -> bool:
        return False

    def execute(self, method: SanitizeMethod) -> bool:
        return False
        
    def get_risk_report(self) -> RiskReport:
        return RiskReport(
            residual_risk_level="HIGH",
            reallocated_sectors_cleared=False,
            hidden_areas_cleared=False,
            notes="No firmware sanitization available."
        )
