import math
import re
from typing import List, Dict


def shannon_entropy(s: str) -> float:
    """Approximate Shannon entropy (bits per character)."""
    if not s:
        return 0.0

    # Count character frequencies
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    # Compute probabilities and sum
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy



def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def is_base64_charset(s: str) -> bool:
    # base64 allowed chars (not enforcing length multiple of 4 yet)
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s))




def detect_string_type(s: str) -> List[Dict]:
    """
    Inspect a string and return guesses about what it might be.
    Each guess: { 'type': ..., 'confidence': float, 'reason': str }
    """
    s = s.strip()
    candidates = []
    length = len(s)
    entropy = shannon_entropy(s)

    # Quick sanity check
    if length == 0:
        return [{"type": "empty", "confidence": 1.0, "reason": "Empty string"}]

    # 1. Bcrypt
    if re.fullmatch(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}", s):
        candidates.append({
            "type": "bcrypt hash",
            "confidence": 0.99,
            "reason": "Matches bcrypt format ($2x$.. with 60 chars)."
        })

    # 2. Hex-based hashes (MD5, SHA1, SHA256, SHA512)
    if is_hex(s):
        if length == 32:
            candidates.append({
                "type": "MD5 hash (hex)",
                "confidence": 0.9,
                "reason": "Length 32 and all hex characters."
            })
        elif length == 40:
            candidates.append({
                "type": "SHA1 hash (hex)",
                "confidence": 0.9,
                "reason": "Length 40 and all hex characters."
            })
        elif length == 64:
            candidates.append({
                "type": "SHA256 hash (hex)",
                "confidence": 0.9,
                "reason": "Length 64 and all hex characters."
            })
        elif length == 128:
            candidates.append({
                "type": "SHA512 hash (hex)",
                "confidence": 0.9,
                "reason": "Length 128 and all hex characters."
            })
        else:
            candidates.append({
                "type": "hex string (unknown hash or data)",
                "confidence": 0.6,
                "reason": f"All hex characters, length {length} not standard hash size."
            })

    # 3. Base64-like
    if is_base64_charset(s):
        base64_reason = f"Uses only base64 characters, length {length}."
        if length % 4 == 0:
            base64_reason += " Length is multiple of 4."
            conf = 0.8
        else:
            base64_reason += " Length is not multiple of 4, possibly truncated or variant."
            conf = 0.4

        candidates.append({
            "type": "Base64 (or similar) encoded data",
            "confidence": conf,
            "reason": base64_reason
        })

    # 4. High-entropy generic hash/encryption guess
    if entropy > 3.5 and length > 16:
        candidates.append({
            "type": "high-entropy string (hash or encrypted data)",
            "confidence": 0.5,
            "reason": f"High Shannon entropy ({entropy:.2f} bits/char). Likely hash or cipher text."
        })

    # If nothing matched, return generic
    if not candidates:
        candidates.append({
            "type": "unknown / likely plain text",
            "confidence": 0.1,
            "reason": f"No typical hash/encoding patterns. Entropy {entropy:.2f} bits/char."
        })

    # Sort by confidence descending
    candidates.sort(key=lambda c: c["confidence"], reverse=True)
    return candidates



if __name__ == "__main__":
    while True:
        s = input("Enter string (or 'exit'): ").strip()
        if s.lower() in ("exit", "quit"):
            break

        results = detect_string_type(s)
        print("\nGuesses:")
        for r in results:
            print(f"- {r['type']} (confidence {r['confidence']:.2f})")
            print(f"  reason: {r['reason']}")
        print()


