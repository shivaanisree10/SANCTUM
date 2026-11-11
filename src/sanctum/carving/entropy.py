import math
from collections import Counter
from sanctum.carving.models import BlockEntropyClass


def calculate_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy for a byte buffer (0.0 to 8.0 bits per byte).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def classify_block(data: bytes) -> BlockEntropyClass:
    """
    Classifies a storage block or sector into entropy tiers.
    """
    if not data or set(data) == {0} or set(data) == {0xFF}:
        return BlockEntropyClass.SPARSE_ZERO

    ent = calculate_entropy(data)
    if ent < 1.0:
        return BlockEntropyClass.SPARSE_ZERO
    elif ent < 6.8:
        return BlockEntropyClass.LOW_TEXT_CODE
    else:
        return BlockEntropyClass.HIGH_COMPRESSED_MEDIA
