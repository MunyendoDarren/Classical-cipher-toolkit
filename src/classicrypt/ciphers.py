"""Classical cipher implementations.

Letter-by-letter ciphers (Caesar, Atbash, Affine, Vigenere, Substitution)
preserve case, spaces and punctuation. Playfair and Columnar Transposition
work on cleaned, upper-case text (A-Z only). Rail Fence works on the raw string.

WARNING: every cipher here is trivially breakable. Use for learning only.
"""

import math
import random
from typing import List, Optional, Sequence

from .utils import ALPHABET, clean, map_char, shift_char

# --------------------------------------------------------------------------- #
# Caesar / ROT13
# --------------------------------------------------------------------------- #


def caesar_encrypt(text: str, shift: int) -> str:
    return "".join(shift_char(c, shift) for c in text)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def rot13(text: str) -> str:
    return caesar_encrypt(text, 13)


# --------------------------------------------------------------------------- #
# Atbash
# --------------------------------------------------------------------------- #

_ATBASH = ALPHABET[::-1]


def atbash(text: str) -> str:
    """Atbash is its own inverse, so one function does both directions."""
    return "".join(map_char(c, _ATBASH) for c in text)


# --------------------------------------------------------------------------- #
# Affine
# --------------------------------------------------------------------------- #

VALID_AFFINE_A = [a for a in range(1, 26) if math.gcd(a, 26) == 1]


def _check_affine(a: int) -> None:
    if math.gcd(a, 26) != 1:
        raise ValueError(f"'a' must be coprime with 26 (valid: {VALID_AFFINE_A})")


def _affine(text: str, a: int, b: int, decrypt: bool) -> str:
    _check_affine(a)
    a_inv = pow(a, -1, 26)
    out = []
    for c in text:
        if "A" <= c <= "Z" or "a" <= c <= "z":
            base = 65 if c.isupper() else 97
            x = ord(c) - base
            y = (a_inv * (x - b)) % 26 if decrypt else (a * x + b) % 26
            out.append(chr(y + base))
        else:
            out.append(c)
    return "".join(out)


def affine_encrypt(text: str, a: int, b: int) -> str:
    return _affine(text, a, b, decrypt=False)


def affine_decrypt(text: str, a: int, b: int) -> str:
    return _affine(text, a, b, decrypt=True)


# --------------------------------------------------------------------------- #
# Vigenere
# --------------------------------------------------------------------------- #


def _vigenere(text: str, key: str, sign: int) -> str:
    k = [ord(c) - 65 for c in clean(key)]
    if not k:
        raise ValueError("Vigenere key must contain at least one letter")
    out, i = [], 0
    for c in text:
        if "A" <= c <= "Z" or "a" <= c <= "z":
            out.append(shift_char(c, sign * k[i % len(k)]))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_encrypt(text: str, key: str) -> str:
    return _vigenere(text, key, +1)


def vigenere_decrypt(text: str, key: str) -> str:
    return _vigenere(text, key, -1)


# --------------------------------------------------------------------------- #
# Monoalphabetic substitution
# --------------------------------------------------------------------------- #


def _check_sub_key(key: str) -> str:
    key = key.upper()
    if sorted(key) != list(ALPHABET):
        raise ValueError("Substitution key must be a permutation of the 26 letters")
    return key


def random_substitution_key(rng: Optional[random.Random] = None) -> str:
    letters = list(ALPHABET)
    (rng or random).shuffle(letters)
    return "".join(letters)


def substitution_encrypt(text: str, key: str) -> str:
    key = _check_sub_key(key)
    return "".join(map_char(c, key) for c in text)


def substitution_decrypt(text: str, key: str) -> str:
    key = _check_sub_key(key)
    inverse = "".join(ALPHABET[key.index(c)] for c in ALPHABET)
    return "".join(map_char(c, inverse) for c in text)


# --------------------------------------------------------------------------- #
# Playfair (I/J merged, 'X' used as filler)
# --------------------------------------------------------------------------- #


def _playfair_square(key: str) -> List[str]:
    seen: List[str] = []
    for c in clean(key).replace("J", "I") + ALPHABET.replace("J", ""):
        if c not in seen:
            seen.append(c)
    return seen  # 25 letters, row-major 5x5


def _playfair_pairs(text: str) -> List[str]:
    text = clean(text).replace("J", "I")
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else None
        if b is None:
            pairs.append(a + "X")
            i += 1
        elif a == b:
            pairs.append(a + ("X" if a != "X" else "Q"))
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def _playfair(pairs: List[str], key: str, direction: int) -> str:
    sq = _playfair_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(sq)}
    out = []
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:
            out.append(sq[r1 * 5 + (c1 + direction) % 5] + sq[r2 * 5 + (c2 + direction) % 5])
        elif c1 == c2:
            out.append(sq[((r1 + direction) % 5) * 5 + c1] + sq[((r2 + direction) % 5) * 5 + c2])
        else:
            out.append(sq[r1 * 5 + c2] + sq[r2 * 5 + c1])
    return "".join(out)


def playfair_encrypt(text: str, key: str) -> str:
    return _playfair(_playfair_pairs(text), key, +1)


def playfair_decrypt(text: str, key: str) -> str:
    """Decrypt. Filler 'X' characters are NOT stripped (inherent to Playfair)."""
    t = clean(text).replace("J", "I")
    if len(t) % 2:
        raise ValueError("Playfair ciphertext must have an even number of letters")
    return _playfair([t[i:i + 2] for i in range(0, len(t), 2)], key, -1)


# --------------------------------------------------------------------------- #
# Rail Fence
# --------------------------------------------------------------------------- #


def _rail_order(n: int, rails: int) -> List[int]:
    """Indices of the plaintext in the order they are read off the rails."""
    if rails < 2:
        raise ValueError("Rail fence needs at least 2 rails")
    if rails >= n:
        return list(range(n))
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    pattern = [cycle[i % len(cycle)] for i in range(n)]
    return sorted(range(n), key=lambda i: (pattern[i], i))


def railfence_encrypt(text: str, rails: int) -> str:
    return "".join(text[i] for i in _rail_order(len(text), rails))


def railfence_decrypt(text: str, rails: int) -> str:
    out = [""] * len(text)
    for ch, idx in zip(text, _rail_order(len(text), rails)):
        out[idx] = ch
    return "".join(out)


# --------------------------------------------------------------------------- #
# Columnar transposition
# --------------------------------------------------------------------------- #


def _column_order(key: str) -> List[int]:
    """Column read-order for a keyword (ties broken left to right)."""
    k = clean(key)
    if not k:
        raise ValueError("Columnar key must contain at least one letter")
    return sorted(range(len(k)), key=lambda i: (k[i], i))


def columnar_encrypt_order(text: str, order: Sequence[int], pad: str = "X") -> str:
    text = clean(text)
    n = len(order)
    text += pad * (-len(text) % n)
    return "".join(text[col::n] for col in order)


def columnar_decrypt_order(text: str, order: Sequence[int]) -> str:
    n = len(order)
    rows = len(text) // n
    cols = {col: text[j * rows:(j + 1) * rows] for j, col in enumerate(order)}
    return "".join(cols[c][r] for r in range(rows) for c in range(n))


def columnar_encrypt(text: str, key: str) -> str:
    return columnar_encrypt_order(text, _column_order(key))


def columnar_decrypt(text: str, key: str) -> str:
    return columnar_decrypt_order(clean(text), _column_order(key))
