import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class SignedWorkOrder(BaseModel):
    order_id: str
    operator: str
    target_serial: str
    policy: str
    issued_at: float = Field(default_factory=time.time)
    expires_at: float
    signature: str = ""

    def compute_signature(self, secret_key: bytes) -> str:
        payload = f"{self.order_id}|{self.operator}|{self.target_serial}|{self.policy}|{self.issued_at}|{self.expires_at}"
        return hmac.new(secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def is_valid(self, secret_key: bytes) -> bool:
        if time.time() > self.expires_at:
            return False
        expected = self.compute_signature(secret_key)
        return hmac.compare_digest(self.signature, expected)

    @classmethod
    def create(cls, order_id: str, operator: str, target_serial: str, policy: str, duration_sec: int = 3600, secret_key: bytes = b"sanctum_work_order_secret") -> "SignedWorkOrder":
        now = time.time()
        order = cls(
            order_id=order_id,
            operator=operator,
            target_serial=target_serial,
            policy=policy,
            issued_at=now,
            expires_at=now + duration_sec,
        )
        order.signature = order.compute_signature(secret_key)
        return order
