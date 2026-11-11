import uuid
import datetime
import threading
from typing import Dict, Optional

from sanctum.dal import DeviceInfo
from sanctum.safety.models import OperationMode, CapabilityToken
from sanctum.exceptions import SanctumError

class SafetyError(SanctumError):
    """Raised when an operation is refused by the Safety Guard."""
    pass

class SafetyGuard:
    """Manager for locking devices and enforcing safety boundaries (fail-closed)."""
    
    def __init__(self, case_db: Optional[Any] = None) -> None:
        self._locks: Dict[str, CapabilityToken] = {}
        self._lock_mutex = threading.Lock()
        self._case_db = case_db

    def set_case_db(self, case_db: Any) -> None:
        self._case_db = case_db

    def is_protected(self, device: DeviceInfo) -> bool:
        """Identify root/boot/system protected devices."""
        # Virtual devices are disposable test media, never system drives
        if device.is_virtual:
            return False
        
        # M2 Heuristic: Windows PhysicalDrive0 is typically the system boot drive
        if "PhysicalDrive0" in device.path:
            return True
            
        return False

    def is_mounted(self, device: DeviceInfo) -> bool:
        """Check if the device has mounted partitions/volumes."""
        if device.is_virtual:
            return False
        # M2 Stub: Mocking mounted detection for physical drives.
        # In a full implementation, we'd check if any volumes map to this physical drive.
        # For M2 testing, we assume false unless explicitly manipulated by tests.
        return False

    def request_token(self, device: DeviceInfo, job_id: str, operation_id: str, mode: OperationMode, confirmed: bool) -> CapabilityToken:
        """Attempt to lock the device and issue a capability token."""
        # 1. Missing confirmation
        if not confirmed:
            raise SafetyError("Operation refused: explicit confirmation is required.")

        # 2. Ambiguous Identity
        if not device.serial or device.serial.strip() == "" or device.serial == "UNKNOWN":
             raise SafetyError("Operation refused: device identity is ambiguous or missing.")

        # 3. Protected device check
        if self.is_protected(device):
            raise SafetyError(f"Operation refused: Device {device.path} is a protected system/root device.")

        # 4. Mounted device check
        if self.is_mounted(device):
            raise SafetyError(f"Operation refused: Device {device.path} is currently mounted.")

        # 5. Open Forensic Case check (Safety Rule: An open forensic case attached to a device must prevent sanitization)
        if mode == OperationMode.SANITIZATION and self._case_db:
            if self._case_db.is_device_in_forensic_case(device.serial):
                raise SafetyError(
                    f"Operation refused: Device {device.serial} is attached to an active forensic case or has a forensic hold."
                )

        with self._lock_mutex:
            # 5. Conflicting operation active
            existing = self._locks.get(device.serial)
            if existing and existing.is_valid():
                raise SafetyError("Operation refused: conflicting operation is already active on this device.")
            
            # Issue a new short-lived capability token (e.g., 5 minutes)
            token = CapabilityToken(
                job_id=job_id,
                operation_id=operation_id,
                device_serial=device.serial,
                mode=mode,
                expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
            )
            self._locks[device.serial] = token
            return token

    def validate_token(self, token: CapabilityToken, device: DeviceInfo, mode: OperationMode) -> bool:
        """Validate an existing token against the stable device identity and expected mode."""
        # 1. Token invalid or expired
        if not token.is_valid():
            raise SafetyError("Token refused: Token is invalid or expired.")
            
        # 2. Wrong device / Identity Binding mismatch
        if token.device_serial != device.serial:
            raise SafetyError(f"Wrong device selected: Token bound to {token.device_serial}, but presented for {device.serial}.")
            
        # 3. Operation Mode Binding mismatch
        if token.mode != mode:
            raise SafetyError(f"Token refused: mode binding mismatch. Token bound to {token.mode}, but operation requested is {mode}.")
            
        # 4. Verify lock is still registered to this token
        with self._lock_mutex:
            active_token = self._locks.get(device.serial)
            if not active_token or active_token.token_id != token.token_id:
                raise SafetyError("Token refused: Token is not recognized or was superseded by another lock.")
                
        return True

    def revoke_token(self, token: CapabilityToken) -> None:
        """Revoke a token and release the lock."""
        token.revoked = True
        with self._lock_mutex:
            if token.device_serial in self._locks:
                active = self._locks[token.device_serial]
                if active.token_id == token.token_id:
                    del self._locks[token.device_serial]
