import random

import pytest

import classicrypt as cc

PLAIN = "Attack at Dawn! Meet me by the old bridge, 9 o'clock."


def test_caesar_known_vector_and_roundtrip():
    assert cc.caesar_encrypt("Hello, World!", 3) == "Khoor, Zruog!"
    assert cc.caesar_decrypt(cc.caesar_encrypt(PLAIN, 17), 17) == PLAIN


def test_rot13_is_involution():
    assert cc.rot13(cc.rot13(PLAIN)) == PLAIN


def test_atbash():
    assert cc.atbash("Hello") == "Svool"
    assert cc.atbash(cc.atbash(PLAIN)) == PLAIN


def test_affine_roundtrip_and_validation():
    assert cc.affine_decrypt(cc.affine_encrypt(PLAIN, 5, 8), 5, 8) == PLAIN
    assert cc.affine_encrypt("AFFINE", 5, 8) == "IHHWVC"
    with pytest.raises(ValueError):
        cc.affine_encrypt(PLAIN, 2, 3)


def test_vigenere_known_vector():
    assert cc.vigenere_encrypt("ATTACK AT DAWN", "LEMON") == "LXFOPV EF RNHR"
    assert cc.vigenere_decrypt("LXFOPV EF RNHR", "LEMON") == "ATTACK AT DAWN"


def test_substitution_roundtrip():
    key = cc.random_substitution_key(random.Random(1))
    assert cc.substitution_decrypt(cc.substitution_encrypt(PLAIN, key), key) == PLAIN
    with pytest.raises(ValueError):
        cc.substitution_encrypt(PLAIN, "ABC")


def test_playfair_known_vector():
    ct = cc.playfair_encrypt("Hide the gold in the tree stump", "PLAYFAIR EXAMPLE")
    assert ct == "BMODZBXDNABEKUDMUIXMMOUVIF"
    assert cc.playfair_decrypt(ct, "PLAYFAIR EXAMPLE").startswith("HIDETHEGOLDINTHETREXESTUMP")


def test_railfence_known_vector_and_roundtrip():
    assert cc.railfence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    for rails in range(2, 8):
        assert cc.railfence_decrypt(cc.railfence_encrypt(PLAIN, rails), rails) == PLAIN


def test_columnar_roundtrip():
    ct = cc.columnar_encrypt("WE ARE DISCOVERED FLEE AT ONCE", "ZEBRAS")
    assert ct == "EVLNXACDTXESEAXROFOXDEECXWIREE"
    assert cc.columnar_decrypt(ct, "ZEBRAS").startswith("WEAREDISCOVEREDFLEEATONCE")
