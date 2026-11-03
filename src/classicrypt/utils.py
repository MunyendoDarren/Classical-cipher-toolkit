"""Small helpers shared by the cipher and analysis modules."""

import string

ALPHABET = string.ascii_uppercase


def clean(text: str) -> str:
    """Return only the A-Z letters of *text*, upper-cased."""
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def shift_char(c: str, k: int) -> str:
    """Shift a single letter by *k* positions, preserving case.

    Non-letters are returned unchanged.
    """
    if "A" <= c <= "Z":
        return chr((ord(c) - 65 + k) % 26 + 65)
    if "a" <= c <= "z":
        return chr((ord(c) - 97 + k) % 26 + 97)
    return c


def map_char(c: str, mapping: str) -> str:
    """Map a letter through a 26-letter substitution string, preserving case."""
    if "A" <= c <= "Z":
        return mapping[ord(c) - 65]
    if "a" <= c <= "z":
        return mapping[ord(c) - 97].lower()
    return c
