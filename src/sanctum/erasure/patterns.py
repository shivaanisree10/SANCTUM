import os
from enum import Enum

class PatternType(str, Enum):
    ZERO = "ZERO"
    ONES = "ONES"
    RANDOM = "RANDOM"

def get_pattern_block(pattern: PatternType, size: int) -> bytes:
    """Generate a block of bytes for the given pattern type."""
    if pattern == PatternType.ZERO:
        return b"\x00" * size
    elif pattern == PatternType.ONES:
        return b"\xFF" * size
    elif pattern == PatternType.RANDOM:
        return os.urandom(size)
    else:
        raise ValueError(f"Unknown pattern type: {pattern}")
