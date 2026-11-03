import random
from pathlib import Path

import classicrypt as cc
from classicrypt.utils import clean

SAMPLE = (Path(__file__).parent.parent / "examples" / "sample_plaintext.txt").read_text().strip()


def test_crack_caesar():
    shift, plain = cc.crack_caesar(cc.caesar_encrypt(SAMPLE, 11))
    assert shift == 11 and plain == SAMPLE


def test_crack_affine():
    (a, b), plain = cc.crack_affine(cc.affine_encrypt(SAMPLE, 7, 3))
    assert (a, b) == (7, 3) and plain == SAMPLE


def test_crack_vigenere():
    for key in ("KEY", "SECRET", "LEMON"):
        found, plain = cc.crack_vigenere(cc.vigenere_encrypt(SAMPLE, key))
        assert found == key and plain == SAMPLE


def test_crack_railfence():
    rails, plain = cc.crack_railfence(cc.railfence_encrypt(SAMPLE, 4))
    assert rails == 4 and plain == SAMPLE


def test_crack_columnar():
    ct = cc.columnar_encrypt(SAMPLE, "CRYPT")
    keyword, plain = cc.crack_columnar(ct)
    assert plain.startswith(clean(SAMPLE)[:100])
    assert cc.columnar_encrypt(SAMPLE, keyword) == ct


def test_crack_substitution_mostly_correct():
    key = cc.random_substitution_key(random.Random(5))
    ct = cc.substitution_encrypt(SAMPLE, key)
    _, plain = cc.crack_substitution(ct, seed=1)
    a, b = clean(plain), clean(SAMPLE)
    accuracy = sum(x == y for x, y in zip(a, b)) / len(b)
    assert accuracy > 0.8      # heuristic attack: expect a near-solution


def test_index_of_coincidence_separates_english_from_random():
    rng = random.Random(0)
    random_text = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5000))
    assert cc.index_of_coincidence(SAMPLE) > 0.06
    assert cc.index_of_coincidence(random_text) < 0.045


def test_fitness_prefers_english():
    assert cc.fitness(SAMPLE) > cc.fitness(cc.caesar_encrypt(SAMPLE, 5))
