"""
Enforcement tests for the v1.0.2 `FPECipher.decrypt()` fix.

v1.0.1 dropped one byte from the deciphered result whenever the *final* Feistel round happened to
end on a null byte, because `extended` (the flag meaning "encryption padded this half, crop it back
off") was set from the *value* of the last byte instead of from the length bookkeeping alone.

The four classes below each pin a different property, so the defect cannot come back unnoticed:

* `TestKnownAnswers`      -- the wire format, using vectors taken from the Golang reference
                             implementation, so they cannot drift along with this library.
* `TestLengthInvariant`   -- the structural property the bug violated: FPE is byte-length
                             preserving in both directions.
* `TestNullByteRegression`-- the exact couples that used to lose a byte.
* `TestExhaustiveBytes`   -- the byte-level API over arbitrary bytes, NUL bytes included, which a
                             UTF-8 text sample structurally cannot reach.
"""

import itertools
import random
import string
from unittest import TestCase

from feistel import FPECipher, BLAKE2B, KECCAK, SHA_256, SHA_3
from feistel.utils import (
    hash,
    hex2Readable,
    readable2bytearray,
    readable2hex,
    split_bytes,
)

KEY = "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692"
KEY2 = "some-32-byte-long-key-to-be-safe"
ENGINES = [SHA_256, BLAKE2B, KECCAK, SHA_3]

# (engine, rounds, key, data) couples that made v1.0.1 take the faulty branch and return one byte
# short. They span the four engines, even lengths 2 to 32, and round counts 2 to 128.
LOSSY_COUPLES = [
    (
        SHA_256,
        10,
        "cdc5b1eb61f68c76d522ba266f4d93b1f812f249b98ce6c38acfd7d56d9b6db6",
        "aH",
    ),
    (
        BLAKE2B,
        10,
        "c046d0d8e15505370f4731a80aa512efd9c4fe2bbfca74e3ce59424c07d6f1a6",
        "YfNU",
    ),
    (
        KECCAK,
        3,
        "c8ca823bc006a787d3286c5e69712deac31d49737ff0693cd07dd5974242f06b",
        "GpbLnM",
    ),
    (
        SHA_3,
        10,
        "cc8299236a5902d0e1303c2b9675b0bfd5900dbbae2f5b075238bb62620d9d98",
        "EErcrnKN",
    ),
    (
        SHA_256,
        11,
        "54c93b022f9739a20533e28f28059dec21d23d129c122614b4f28a6d4c568556",
        "LEtAhEKfpkjLXgbI",
    ),
    (
        SHA_256,
        2,
        "3769d73cd23cf8808f2ef67419ad77474c61954624d47b547e6c876677ab4a0b",
        "edkPGaIFJmNFPqlaqxIGTVGrCsvfyCcF",
    ),
    (
        SHA_256,
        12,
        "ffd1ff797a23c9d9352bee1e2a49f0a871c7ce7f77b4939ac9acf6e4247a9398",
        "iNVUfwtHQp",
    ),
    (
        SHA_256,
        128,
        "3d8c35b880b5c6d11c2025e1c3fee6fde9e67c7e36a19bc512af7c2003b38e18",
        "UeoC",
    ),
]


class TestKnownAnswers(TestCase):
    """
    Wire-format lock. Every vector here is copied from the test suite of the Golang reference
    implementation (`feistel/fpe_test.go`), not produced by this library, so it is an independent
    check: any change altering what `encrypt()` writes or what `decrypt()` reads breaks these, and
    data already stored in production becomes undecipherable.
    """

    def test_encrypt(self):
        cipher = FPECipher(SHA_256, KEY, 10)
        found = cipher.encrypt("Edgewhere")
        self.assertEqual(str(found), "K¡(#q|r5*")
        self.assertEqual(readable2hex(found), "2a5d07024f5a501409")
        self.assertEqual(len(found), len("Edgewhere"))

        # Golang asserts the Blake2b ciphertext too, which this suite only checked on decrypt
        blake2 = FPECipher(BLAKE2B, KEY, 10).encrypt("Edgewhere")
        self.assertEqual(str(blake2), "¼u*$q0up¢")

    def test_decrypt(self):
        cipher = FPECipher(SHA_256, KEY, 10)
        # This vector is the *padded* output of the non-FPE `Cipher`, so the deciphered
        # plaintext legitimately keeps its leading U+0002 padding byte: 10 bytes in, 10 out.
        self.assertEqual(
            cipher.decrypt(hex2Readable("3d7c0a0f51415a521054")), "\u0002Edgewhere"
        )
        self.assertEqual(
            cipher.decrypt(hex2Readable("2a5d07024f5a501409")), "Edgewhere"
        )

    def test_readable_string(self):
        # Golang TestReadableString: an even-length input, i.e. one the v1.0.1 bug could hit
        cipher = FPECipher(SHA_256, KEY2, 128)
        obfuscated = cipher.encrypt_string("my-source-data")
        self.assertEqual(
            list(readable2bytearray(obfuscated)),
            [62, 125, 126, 123, 99, 124, 118, 109, 108, 121, 97, 49, 33, 101],
        )
        self.assertEqual(str(obfuscated), "`ÃÄÁ§Â¼²±¿¥RB©")
        self.assertEqual(cipher.decrypt_string(obfuscated), "my-source-data")

    def test_high_and_odd_round_counts(self):
        # Golang TestFPEEncryptDecrypt uses 255 rounds; an odd count takes the rebalancing
        # branch at the top of `decrypt_bytes()`
        for rounds in (2, 3, 127, 128, 255):
            cipher = FPECipher(SHA_256, KEY, rounds)
            self.assertEqual(cipher.decrypt(cipher.encrypt("Edgewhere")), "Edgewhere")


class TestLengthInvariant(TestCase):
    """
    `FPECipher` applies no padding at all -- unlike `Cipher`, which pads odd input with `pad()` and
    strips it with `unpad()`, and may therefore legitimately return fewer characters than it got.
    FPE has no such licence: it owes exactly as many bytes back as it was handed, in both
    directions. That is precisely the invariant the removed heuristic broke, so asserting it
    catches any reintroduction immediately, whatever the trigger.
    """

    def test_split_bytes_halves_differ_by_at_most_one(self):
        # The premise of the shape analysis: only three shapes exist for (left, right)
        for n in range(0, 130):
            left, right = split_bytes(bytearray(n))
            self.assertEqual(len(left) + len(right), n)
            self.assertIn(len(right) - len(left), (0, 1))

    def test_length_preserved_on_known_trigger_couples(self):
        """
        Deterministic guard on the *property* rather than the values: these couples all drive the
        final round onto a null byte, so any variant of the old heuristic shortens the result here
        even if someone edits the expected plaintexts elsewhere.
        """
        for engine, rounds, key, data in LOSSY_COUPLES:
            cipher = FPECipher(engine, key, rounds)
            raw = bytearray(data, "utf-8")
            ciphered = cipher.encrypt_bytes(raw.copy())
            self.assertEqual(len(ciphered), len(raw))
            self.assertEqual(
                len(cipher.decrypt_bytes(ciphered.copy())),
                len(raw),
                msg=f"decrypt shortened the result for {data!r} "
                f"(engine={engine}, rounds={rounds})",
            )

    def test_encrypt_and_decrypt_preserve_byte_length(self):
        rng = random.Random(20260906)
        for n in range(1, 40):
            for rounds in (2, 3, 4, 5, 10, 11):
                cipher = FPECipher(ENGINES[n % len(ENGINES)], KEY, rounds)
                data = bytearray(rng.getrandbits(8) for _ in range(n))
                ciphered = cipher.encrypt_bytes(data.copy())
                self.assertEqual(
                    len(ciphered), n, msg=f"encrypt lost bytes: n={n} rounds={rounds}"
                )
                deciphered = cipher.decrypt_bytes(ciphered.copy())
                self.assertEqual(
                    len(deciphered), n, msg=f"decrypt lost bytes: n={n} rounds={rounds}"
                )


class TestNullByteRegression(TestCase):
    """
    Canaries: each couple below made v1.0.1 take the faulty branch and return one byte short.
    They span the four engines, even lengths from 2 to 32, and round counts from 2 to 128.
    Note that only *even* byte lengths were ever affected: for an odd length the final round always
    lands on the shape where `extended` is legitimately set already, making the heuristic a no-op.
    """

    def test_minimal_case(self):
        # The smallest reproduction: 'ef' used to decipher as 'f'
        cipher = FPECipher(SHA_256, hash(bytearray.fromhex("a" * 64)).hex(), 10)
        obfuscated = cipher.encrypt("ef")
        self.assertEqual(len(obfuscated), 2)
        self.assertEqual(cipher.decrypt(obfuscated), "ef")

    def test_known_lossy_couples(self):
        for engine, rounds, key, data in LOSSY_COUPLES:
            cipher = FPECipher(engine, key, rounds)
            obfuscated = cipher.encrypt(data)
            self.assertEqual(len(obfuscated), len(data))
            self.assertEqual(
                cipher.decrypt(obfuscated),
                data,
                msg=f"regression on {data!r} (engine={engine}, rounds={rounds})",
            )


class TestExhaustiveBytes(TestCase):
    """
    The bug branched on a byte *value* being 0x00, which a UTF-8 text sample can never produce.
    These go through the byte-level API with arbitrary bytes so the null cases are actually covered.
    """

    def _roundtrip(self, data, rounds, engine=SHA_256, key=KEY):
        cipher = FPECipher(engine, key, rounds)
        ciphered = cipher.encrypt_bytes(bytearray(data))
        self.assertEqual(len(ciphered), len(data))
        self.assertEqual(cipher.decrypt_bytes(ciphered.copy()), bytearray(data))

    def test_every_one_byte_array(self):
        for engine in ENGINES:
            for value in range(256):
                self._roundtrip([value], 10, engine)

    def test_every_two_byte_array(self):
        # Exhaustive: covers a NUL in either half, at the lowest even length the bug could hit
        for rounds in (2, 3):
            for pair in itertools.product(range(256), repeat=2):
                self._roundtrip(pair, rounds)

    def test_nul_heavy_patterns(self):
        # Exhaustive over an alphabet built around the boundary values, lengths 3 to 5
        for n in (3, 4, 5):
            for pattern in itertools.product([0, 1, 127, 128, 255], repeat=n):
                self._roundtrip(pattern, 10)

    def test_random_arbitrary_bytes(self):
        rng = random.Random(1102)
        for _ in range(4000):
            n = rng.randint(1, 33)
            # 30% NUL density, so trailing and interior nulls turn up often
            data = [0 if rng.random() < 0.3 else rng.getrandbits(8) for _ in range(n)]
            self._roundtrip(data, rng.choice([2, 3, 10, 11]), rng.choice(ENGINES))

    def test_non_utf8_bytes_survive(self):
        # Byte arrays that are not valid UTF-8 at all must still round-trip through the byte API
        for data in (
            [0xFF, 0xFE],
            [0x80, 0x80, 0x80, 0x80],
            [0xC3],
            [0x00, 0x00],
            [0xED, 0xA0, 0x80],
        ):
            self._roundtrip(data, 10)
