"""Command-line interface:  classicrypt {encrypt,decrypt,crack,analyze} ..."""

import argparse
import sys
from typing import Callable, Dict, Tuple

from . import __version__, analysis, attacks, ciphers

# name -> (encrypt, decrypt, key parser or None when the cipher is keyless)


def _int(k: str) -> int:
    return int(k)


def _pair(k: str) -> Tuple[int, int]:
    a, b = k.split(",")
    return int(a), int(b)


CIPHERS: Dict[str, Tuple[Callable, Callable, object]] = {
    "caesar": (ciphers.caesar_encrypt, ciphers.caesar_decrypt, _int),
    "rot13": (lambda t: ciphers.rot13(t), lambda t: ciphers.rot13(t), None),
    "atbash": (lambda t: ciphers.atbash(t), lambda t: ciphers.atbash(t), None),
    "affine": (lambda t, k: ciphers.affine_encrypt(t, *k), lambda t, k: ciphers.affine_decrypt(t, *k), _pair),
    "vigenere": (ciphers.vigenere_encrypt, ciphers.vigenere_decrypt, str),
    "playfair": (ciphers.playfair_encrypt, ciphers.playfair_decrypt, str),
    "railfence": (ciphers.railfence_encrypt, ciphers.railfence_decrypt, _int),
    "columnar": (ciphers.columnar_encrypt, ciphers.columnar_decrypt, str),
    "substitution": (ciphers.substitution_encrypt, ciphers.substitution_decrypt, str),
}

CRACKABLE = ["caesar", "affine", "vigenere", "substitution", "railfence", "columnar"]


def _read_text(args) -> str:
    if args.text is not None:
        return args.text
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def _add_input(p: argparse.ArgumentParser) -> None:
    p.add_argument("-t", "--text", help="text to process (otherwise --file or stdin)")
    p.add_argument("-f", "--file", help="read text from a file")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="classicrypt",
        description="Educational toolkit: classical ciphers and cryptanalysis.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    for name in ("encrypt", "decrypt"):
        sp = sub.add_parser(name, help=f"{name} text with a classical cipher")
        sp.add_argument("cipher", choices=sorted(CIPHERS))
        sp.add_argument("-k", "--key", help="key (caesar: 3 | affine: 5,8 | vigenere: LEMON | "
                        "railfence: 3 | columnar: ZEBRAS | substitution: 26 letters)")
        _add_input(sp)

    sp = sub.add_parser("crack", help="automatically attack a ciphertext")
    sp.add_argument("cipher", choices=CRACKABLE)
    sp.add_argument("--max-key-len", type=int, default=16, help="vigenere: longest key to try")
    sp.add_argument("--max-rails", type=int, default=10, help="railfence: most rails to try")
    sp.add_argument("--max-cols", type=int, default=7, help="columnar: most columns to try (<= 8)")
    _add_input(sp)

    sp = sub.add_parser("analyze", help="frequency analysis, index of coincidence, key-length hints")
    _add_input(sp)
    return p


def _run_cipher(args) -> str:
    enc, dec, parse = CIPHERS[args.cipher]
    func = enc if args.command == "encrypt" else dec
    text = _read_text(args)
    if parse is None:
        return func(text)
    if args.key is None:
        raise SystemExit(f"error: cipher '{args.cipher}' needs --key")
    return func(text, parse(args.key))


def _run_crack(args) -> str:
    text = _read_text(args)
    c = args.cipher
    if c == "caesar":
        shift, plain = attacks.crack_caesar(text)
        return f"[key] shift = {shift}\n{plain}"
    if c == "affine":
        (a, b), plain = attacks.crack_affine(text)
        return f"[key] a = {a}, b = {b}\n{plain}"
    if c == "vigenere":
        key, plain = attacks.crack_vigenere(text, args.max_key_len)
        return f"[key] {key}\n{plain}"
    if c == "substitution":
        key, plain = attacks.crack_substitution(text, seed=1)
        return f"[key] {key}\n{plain}"
    if c == "railfence":
        rails, plain = attacks.crack_railfence(text, args.max_rails)
        return f"[key] rails = {rails}\n{plain}"
    key, plain = attacks.crack_columnar(text, args.max_cols)
    return f"[key] {key}\n{plain}"


def _run_analyze(args) -> str:
    text = _read_text(args)
    freqs = analysis.letter_frequencies(text)
    lines = [
        f"Letters analysed : {len(analysis.clean(text))}",
        f"Index of coincidence : {analysis.index_of_coincidence(text):.4f}"
        "   (English ~0.066, random ~0.038)",
        f"Chi-squared vs English : {analysis.chi_squared(text):.1f}",
        "",
        "Letter frequencies:",
    ]
    for letter, pct in sorted(freqs.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {letter} {pct:5.2f}% {'#' * int(round(pct * 2))}")
    kas = analysis.kasiski_key_lengths(text)[:5]
    if kas:
        lines += ["", "Kasiski - likely key lengths (length: votes): "
                  + ", ".join(f"{k}: {v}" for k, v in kas)]
    ic = analysis.ic_key_lengths(text)[:5]
    lines += ["IC - likely key lengths (length: avg IC): "
              + ", ".join(f"{k}: {v:.3f}" for k, v in ic)]
    return "\n".join(lines)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command in ("encrypt", "decrypt"):
            out = _run_cipher(args)
        elif args.command == "crack":
            out = _run_crack(args)
        else:
            out = _run_analyze(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
