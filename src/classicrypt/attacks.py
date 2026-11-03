"""Automated cryptanalysis of the classical ciphers in this package."""

import random
from itertools import permutations
from typing import Dict, List, Optional, Tuple

from .analysis import (
    BIGRAM_LOG,
    ENGLISH_FREQ,
    TRIGRAM_BONUS,
    chi_squared,
    fitness,
    index_of_coincidence,
)
from .ciphers import (
    VALID_AFFINE_A,
    affine_decrypt,
    caesar_decrypt,
    columnar_decrypt_order,
    railfence_decrypt,
    substitution_decrypt,
    vigenere_decrypt,
)
from .utils import ALPHABET, clean

# --------------------------------------------------------------------------- #
# Caesar & Affine
# --------------------------------------------------------------------------- #


def caesar_bruteforce(ciphertext: str) -> List[Tuple[int, str, float]]:
    """All 26 candidates as (shift, plaintext, chi_squared), best first."""
    results = [(s, caesar_decrypt(ciphertext, s)) for s in range(26)]
    scored = [(s, p, chi_squared(p)) for s, p in results]
    return sorted(scored, key=lambda x: x[2])


def crack_caesar(ciphertext: str) -> Tuple[int, str]:
    """Return (shift, plaintext) using chi-squared scoring."""
    shift, plain, _ = caesar_bruteforce(ciphertext)[0]
    return shift, plain


def crack_affine(ciphertext: str) -> Tuple[Tuple[int, int], str]:
    """Try all 312 affine keys. Returns ((a, b), plaintext)."""
    best, best_score = None, float("inf")
    for a in VALID_AFFINE_A:
        for b in range(26):
            plain = affine_decrypt(ciphertext, a, b)
            score = chi_squared(plain)
            if score < best_score:
                best, best_score = (a, b, plain), score
    return (best[0], best[1]), best[2]


# --------------------------------------------------------------------------- #
# Vigenere
# --------------------------------------------------------------------------- #


def crack_vigenere(ciphertext: str, max_key_len: int = 16) -> Tuple[str, str]:
    """Recover a Vigenere key. Returns (key, plaintext).

    1. Key length: for each length, average the index of coincidence of the
       columns. The shortest length scoring close to the best is chosen
       (multiples of the true length score well too).
    2. Key letters: each column is a Caesar cipher, solved with chi-squared.

    Needs a reasonable amount of ciphertext (roughly 50+ letters per key letter).
    """
    letters = clean(ciphertext)
    scores = {}
    for length in range(1, min(max_key_len, len(letters) // 2) + 1):
        cols = [letters[i::length] for i in range(length)]
        scores[length] = sum(index_of_coincidence(c) for c in cols) / length
    best_ic = max(scores.values())
    length = min(k for k, v in scores.items() if v >= 0.9 * best_ic)

    key = ""
    for col in range(length):
        column = letters[col::length]
        shift = min(range(26), key=lambda s: chi_squared(caesar_decrypt(column, s)))
        key += ALPHABET[shift]
    return key, vigenere_decrypt(ciphertext, key)


# --------------------------------------------------------------------------- #
# Monoalphabetic substitution - hill climbing
# --------------------------------------------------------------------------- #


def crack_substitution(
    ciphertext: str,
    restarts: int = 6,
    seed: Optional[int] = None,
) -> Tuple[str, str]:
    """Hill-climbing attack on a monoalphabetic substitution cipher.

    Starts from a frequency-analysis guess, then repeatedly swaps pairs of key
    letters, keeping a swap whenever the English bigram/trigram score improves.
    Returns (encryption_key, plaintext) where encryption_key maps A..Z to the
    cipher alphabet (compatible with substitution_decrypt). Works best with
    ~300+ letters of ciphertext. Result is heuristic - check the output.
    """
    rng = random.Random(seed)
    idx = [ord(c) - 65 for c in clean(ciphertext)]
    if len(idx) < 3:
        raise ValueError("ciphertext too short")

    bi: Dict[Tuple[int, int], int] = {}
    tri: Dict[Tuple[int, int, int], int] = {}
    for i in range(len(idx) - 1):
        bi[(idx[i], idx[i + 1])] = bi.get((idx[i], idx[i + 1]), 0) + 1
    for i in range(len(idx) - 2):
        t = (idx[i], idx[i + 1], idx[i + 2])
        tri[t] = tri.get(t, 0) + 1

    bl = [[BIGRAM_LOG[ALPHABET[a] + ALPHABET[b]] for b in range(26)] for a in range(26)]
    tb = {tuple(ord(c) - 65 for c in t): v for t, v in TRIGRAM_BONUS.items()}
    bi_items = list(bi.items())
    tri_items = list(tri.items())

    def score(key: List[int]) -> float:
        s = sum(n * bl[key[a]][key[b]] for (a, b), n in bi_items)
        for (a, b, c), n in tri_items:
            bonus = tb.get((key[a], key[b], key[c]))
            if bonus:
                s += n * bonus
        return s

    # Initial guess: i-th most common cipher letter -> i-th most common English letter.
    counts = [0] * 26
    for v in idx:
        counts[v] += 1
    cipher_rank = sorted(range(26), key=lambda c: -counts[c])
    english_rank = sorted(range(26), key=lambda p: -ENGLISH_FREQ[p])
    base = [0] * 26
    for c, p in zip(cipher_rank, english_rank):
        base[c] = p

    best_key, best_score = base[:], score(base)
    for attempt in range(restarts):
        key = base[:]
        for _ in range(attempt * 3):                  # perturb on later restarts
            i, j = rng.sample(range(26), 2)
            key[i], key[j] = key[j], key[i]
        current = score(key)
        improved = True
        while improved:
            improved = False
            for i in range(25):
                for j in range(i + 1, 26):
                    key[i], key[j] = key[j], key[i]
                    s = score(key)
                    if s > current:
                        current, improved = s, True
                    else:
                        key[i], key[j] = key[j], key[i]
        if current > best_score:
            best_key, best_score = key[:], current

    enc_key = [""] * 26                                # plain letter -> cipher letter
    for c, p in enumerate(best_key):
        enc_key[p] = ALPHABET[c]
    enc_key_str = "".join(enc_key)
    return enc_key_str, substitution_decrypt(ciphertext, enc_key_str)


# --------------------------------------------------------------------------- #
# Transposition ciphers
# --------------------------------------------------------------------------- #


def crack_railfence(ciphertext: str, max_rails: int = 10) -> Tuple[int, str]:
    """Try 2..max_rails rails and keep the most English-looking. Returns (rails, plaintext)."""
    best, best_score = None, float("-inf")
    for rails in range(2, min(max_rails, len(ciphertext) - 1) + 1):
        plain = railfence_decrypt(ciphertext, rails)
        s = fitness(plain)
        if s > best_score:
            best, best_score = (rails, plain), s
    return best


def crack_columnar(ciphertext: str, max_cols: int = 7) -> Tuple[str, str]:
    """Brute-force every column permutation for 2..max_cols columns.

    Returns (keyword, plaintext). Cost grows as max_cols! - keep it <= 8.
    """
    text = clean(ciphertext)
    best, best_score = None, float("-inf")
    for n in range(2, max_cols + 1):
        if len(text) % n:
            continue
        for order in permutations(range(n)):
            plain = columnar_decrypt_order(text, order)
            s = fitness(plain)
            if s > best_score:
                keyword = "".join(ALPHABET[order.index(col)] for col in range(n))
                best, best_score = (keyword, plain), s
    if best is None:
        raise ValueError("no column count up to max_cols divides the ciphertext length")
    return best
