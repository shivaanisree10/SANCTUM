import uuid
import datetime
from enum import Enum
from pydantic import BaseModel, Field

class OperationMode(str, Enum):
    ACQUISITION = "ACQUISITION"
    SANITIZATION = "SANITIZATION"
    ASSURANCE = "ASSURANCE"

class CapabilityToken(BaseModel):
    """Token bound to a specific device, operation, and job with an expiration."""
    token_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    job_id: str
    operation_id: str
    device_serial: str
    mode: OperationMode
    expires_at: datetime.datetime
    revoked: bool = False

    def is_valid(self) -> bool:
        """Check if the token is active and not expired."""
        if self.revoked:
            return False
        # Fail closed on expiration
        if datetime.datetime.now(datetime.timezone.utc) > self.expires_at:
            return False
        return True
