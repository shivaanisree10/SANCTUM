from typing import List, Optional
from enum import Enum
from pydantic import BaseModel
from sanctum.erasure.patterns import PatternType

class MediaClass(str, Enum):
    MAGNETIC = "MAGNETIC"
    SOLID_STATE = "SOLID_STATE"
    VIRTUAL = "VIRTUAL"
    ANY = "ANY"

class VerificationRequirement(str, Enum):
    NONE = "NONE"
    LAST_PASS = "LAST_PASS"
    ALL_PASSES = "ALL_PASSES"

class ErasurePolicy(BaseModel):
    name: str
    description: str
    reference: str
    category: str
    passes: List[PatternType]
    verification: VerificationRequirement
    applicable_media: List[MediaClass]
    version: str
    advisory: Optional[str] = None
