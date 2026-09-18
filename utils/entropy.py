"""
utils/entropy.py
Shannon entropy calculation for raw bytes.
"""

import math


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte sequence.
    Returns value between 0.0 (uniform) and 8.0 (random/encrypted).
    """
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    length  = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)
