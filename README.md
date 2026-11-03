# classicrypt — Classical Cipher Toolkit

[![CI](https://github.com/YOUR-USERNAME/classical-cipher-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/classical-cipher-toolkit/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An educational, dependency-free Python toolkit that **implements classical ciphers and breaks them**.
It pairs each cipher with the cryptanalysis technique that defeats it, which makes it a hands-on
way to learn *why* these ciphers failed and what modern cryptography had to fix.

> **Disclaimer:** every cipher here is insecure by modern standards. This project is for learning
> and CTF practice only — never use it to protect real data.

## Features

| Cipher | Encrypt / Decrypt | Automated attack |
|---|---|---|
| Caesar / ROT13 | yes | brute force + chi-squared |
| Atbash | yes | trivial (keyless) |
| Affine | yes | all 312 keys + chi-squared |
| Vigenère | yes | index of coincidence + per-column chi-squared (Kasiski helper included) |
| Monoalphabetic substitution | yes | frequency analysis + bigram/trigram hill climbing |
| Playfair | yes | — (see roadmap) |
| Rail Fence | yes | try all rail counts, score with n-gram fitness |
| Columnar transposition | yes | brute-force column permutations, n-gram fitness |

Analysis tools: letter frequencies, index of coincidence, chi-squared, Kasiski examination,
n-gram English fitness score.

## Install

```bash
git clone https://github.com/YOUR-USERNAME/classical-cipher-toolkit.git
cd classical-cipher-toolkit
pip install -e .
```

## CLI usage

```bash
# Encrypt / decrypt
classicrypt encrypt caesar    -k 3        -t "Hello, World!"
classicrypt encrypt affine    -k 5,8      -t "Affine cipher"
classicrypt encrypt vigenere  -k LEMON    -t "Attack at dawn"
classicrypt encrypt playfair  -k "PLAYFAIR EXAMPLE" -t "Hide the gold in the tree stump"
classicrypt encrypt railfence -k 3        -t "WEAREDISCOVEREDFLEEATONCE"
classicrypt decrypt columnar  -k ZEBRAS   -f cipher.txt

# Crack without the key
classicrypt crack caesar       -t "Wkh txlfn eurzq ira"
classicrypt crack vigenere     -f secret.txt
classicrypt crack substitution -f secret.txt

# Analyse an unknown ciphertext
classicrypt analyze -f secret.txt
```

Input comes from `-t TEXT`, `-f FILE`, or stdin (`cat msg.txt | classicrypt crack caesar`).

## Library usage

```python
import classicrypt as cc

ct = cc.vigenere_encrypt("Attack at dawn", "LEMON")        # 'Lxfopv ef rnhr'
key, plain = cc.crack_vigenere(long_ciphertext)

cc.index_of_coincidence(text)     # ~0.066 English, ~0.038 random
cc.kasiski_key_lengths(text)      # candidate Vigenère key lengths
```

Run `python examples/demo.py` for a guided tour.

## How the attacks work

- **Chi-squared (Caesar, Affine, Vigenère columns):** compares letter counts to English
  frequencies; the correct shift gives the lowest distance.
- **Index of coincidence (Vigenère):** English text has IC ≈ 0.066. Splitting the ciphertext into
  *k* columns and averaging their IC reveals the key length, because the right *k* turns each column
  into a plain Caesar cipher.
- **Kasiski examination:** repeated ciphertext sequences are usually repeated plaintext under the
  same key position, so their distances are multiples of the key length.
- **Hill climbing (substitution):** start from a frequency-rank guess, then keep any letter swap that
  improves an English bigram/trigram score. Expect roughly 90% correct letters on ~1000 letters of
  text; shorter messages give weaker results (the output is a near-solution you finish by eye).
- **N-gram fitness (transposition):** transposition keeps letter frequencies unchanged, so we score
  *letter order* instead.

### Known limits

- Vigenère cracking needs enough text (about 50+ letters per key letter).
- Columnar brute force is `n!`, so `--max-cols` should stay at 8 or below.
- Playfair decryption does not strip filler `X` letters (inherent to the cipher).

## Project layout

```
src/classicrypt/
  ciphers.py    cipher implementations
  analysis.py   frequency, IC, chi-squared, Kasiski, n-gram fitness
  attacks.py    automated cryptanalysis
  cli.py        command-line interface
tests/          pytest suite (known test vectors + attack checks)
examples/       demo script and sample text
```

## Tests

```bash
pip install pytest
pytest
```

## Roadmap

- [ ] Playfair attack (simulated annealing)
- [ ] Hill cipher + known-plaintext attack
- [ ] Autokey and Beaufort ciphers
- [ ] Quadgram statistics for stronger substitution cracking
- [ ] Simple web UI

## License

MIT — see [LICENSE](LICENSE).
