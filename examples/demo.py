"""Run with:  python examples/demo.py   (after `pip install -e .`)"""

import random

import classicrypt as cc

plaintext = open(__file__.replace("demo.py", "sample_plaintext.txt")).read().strip()

print("== Caesar: encrypt, then crack without the key ==")
ct = cc.caesar_encrypt(plaintext, 7)
shift, plain = cc.crack_caesar(ct)
print("recovered shift:", shift, "|", plain[:60], "...\n")

print("== Vigenere: Kasiski + IC + chi-squared ==")
ct = cc.vigenere_encrypt(plaintext, "ENIGMA")
print("Kasiski guesses :", cc.kasiski_key_lengths(ct)[:3])
key, plain = cc.crack_vigenere(ct)
print("recovered key   :", key, "|", plain[:60], "...\n")

print("== Substitution: hill-climbing ==")
secret = cc.random_substitution_key(random.Random(42))
ct = cc.substitution_encrypt(plaintext, secret)
_, plain = cc.crack_substitution(ct, seed=1)
print(plain[:120], "...")
