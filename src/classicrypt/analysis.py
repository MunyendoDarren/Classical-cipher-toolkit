"""Statistical tools used to analyse and attack classical ciphers."""

import math
from collections import Counter
from typing import Dict, List, Tuple

from .utils import ALPHABET, clean

# Relative frequency (%) of letters in English text, A..Z.
ENGLISH_FREQ = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]

# Approximate frequency (per thousand bigrams / trigrams) in English text.
BIGRAMS: Dict[str, float] = {
    "TH": 35.6, "HE": 30.7, "IN": 24.3, "ER": 20.5, "AN": 19.9, "RE": 18.5,
    "ON": 17.6, "AT": 14.9, "EN": 14.5, "ND": 13.5, "TI": 13.4, "ES": 13.4,
    "OR": 12.8, "TE": 12.0, "OF": 11.7, "ED": 11.7, "IS": 11.3, "IT": 11.2,
    "AL": 10.9, "AR": 10.7, "ST": 10.5, "TO": 10.5, "NT": 10.4, "NG": 9.5,
    "SE": 9.3, "HA": 9.3, "AS": 8.7, "OU": 8.7, "IO": 8.3, "LE": 8.3,
    "VE": 8.3, "CO": 7.9, "ME": 7.9, "DE": 7.6, "HI": 7.6, "RI": 7.3,
    "RO": 7.3, "IC": 7.0, "NE": 6.9, "EA": 6.9, "RA": 6.9, "CE": 6.5,
    "LI": 6.2, "CH": 6.0, "LL": 5.8, "BE": 5.8, "MA": 5.7, "SI": 5.5,
    "OM": 5.5, "UR": 5.4,
}
TRIGRAMS: Dict[str, float] = {
    "THE": 18.1, "AND": 7.3, "ING": 7.2, "ENT": 4.2, "ION": 4.2, "HER": 3.6,
    "FOR": 3.4, "THA": 3.3, "NTH": 3.3, "INT": 3.2, "ERE": 3.1, "TIO": 3.1,
    "TER": 3.0, "EST": 2.8, "ERS": 2.8, "ATI": 2.6, "HAT": 2.6, "ATE": 2.5,
    "ALL": 2.5, "ETH": 2.4, "HES": 2.4, "VER": 2.4, "HIS": 2.4, "OFT": 2.2,
    "ITH": 2.1, "FTH": 2.1, "STH": 2.1, "OTH": 2.1, "RES": 2.1, "ONT": 2.0,
}
BIGRAM_FLOOR = 0.1   # per thousand, for bigrams not in the table
TRIGRAM_FLOOR = 0.2

BIGRAM_LOG: Dict[str, float] = {
    a + b: math.log10(BIGRAMS.get(a + b, BIGRAM_FLOOR))
    for a in ALPHABET for b in ALPHABET
}
TRIGRAM_BONUS: Dict[str, float] = {
    t: math.log10(f / TRIGRAM_FLOOR) for t, f in TRIGRAMS.items()
}


def letter_counts(text: str) -> Counter:
    return Counter(clean(text))


def letter_frequencies(text: str) -> Dict[str, float]:
    """Percentage frequency of each letter A-Z in *text*."""
    counts = letter_counts(text)
    total = sum(counts.values()) or 1
    return {c: 100.0 * counts.get(c, 0) / total for c in ALPHABET}


def index_of_coincidence(text: str) -> float:
    """Probability that two random letters of *text* are equal.

    English ~ 0.066, uniformly random letters ~ 0.038.
    """
    counts = letter_counts(text)
    n = sum(counts.values())
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def chi_squared(text: str) -> float:
    """Chi-squared distance from English letter frequencies (lower = more English)."""
    counts = letter_counts(text)
    n = sum(counts.values())
    if n == 0:
        return float("inf")
    return sum(
        (counts.get(c, 0) - n * ENGLISH_FREQ[i] / 100.0) ** 2 / (n * ENGLISH_FREQ[i] / 100.0)
        for i, c in enumerate(ALPHABET)
    )


def fitness(text: str) -> float:
    """Heuristic 'how English is this?' score (higher = more English).

    Based on bigram log-probabilities plus a bonus for common trigrams. Unlike
    chi_squared it is sensitive to letter ORDER, so it works for transposition
    ciphers. Only compare scores of texts of similar length.
    """
    t = clean(text)
    if len(t) < 2:
        return float("-inf")
    score = sum(BIGRAM_LOG[t[i:i + 2]] for i in range(len(t) - 1))
    score += sum(TRIGRAM_BONUS.get(t[i:i + 3], 0.0) for i in range(len(t) - 2))
    return score / (len(t) - 1)


def kasiski_key_lengths(text: str, max_len: int = 20, seq_len: int = 3) -> List[Tuple[int, int]]:
    """Kasiski examination.

    Finds repeated sequences, measures the distances between repeats and counts
    how often each candidate key length divides those distances.
    Returns [(key_length, votes), ...] sorted by votes (descending).
    """
    t = clean(text)
    positions: Dict[str, List[int]] = {}
    for i in range(len(t) - seq_len + 1):
        positions.setdefault(t[i:i + seq_len], []).append(i)
    votes: Counter = Counter()
    for pos in positions.values():
        for a in range(len(pos)):
            for b in range(a + 1, len(pos)):
                d = pos[b] - pos[a]
                for k in range(2, max_len + 1):
                    if d % k == 0:
                        votes[k] += 1
    return votes.most_common()


def ic_key_lengths(text: str, max_len: int = 20) -> List[Tuple[int, float]]:
    """Average index of coincidence of the columns for each key length.

    A value close to 0.066 suggests the right key length (multiples of the true
    length score well too). Returns [(length, avg_ic), ...] best first.
    """
    t = clean(text)
    scored = []
    for k in range(1, max_len + 1):
        cols = [t[i::k] for i in range(k)]
        scored.append((k, sum(index_of_coincidence(c) for c in cols) / k))
    return sorted(scored, key=lambda x: -x[1])
