"""classicrypt - an educational toolkit of classical ciphers and cryptanalysis tools."""

from .ciphers import (
    atbash,
    caesar_decrypt,
    caesar_encrypt,
    affine_decrypt,
    affine_encrypt,
    columnar_decrypt,
    columnar_encrypt,
    playfair_decrypt,
    playfair_encrypt,
    railfence_decrypt,
    railfence_encrypt,
    random_substitution_key,
    rot13,
    substitution_decrypt,
    substitution_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)
from .analysis import (
    chi_squared,
    fitness,
    index_of_coincidence,
    kasiski_key_lengths,
    letter_frequencies,
)
from .attacks import (
    crack_affine,
    crack_caesar,
    crack_columnar,
    crack_railfence,
    crack_substitution,
    crack_vigenere,
)

__version__ = "1.0.0"
