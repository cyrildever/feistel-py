import random
import string
from unittest import TestCase

from feistel import FPECipher, Readable, hex2Readable, BLAKE2B, KECCAK, SHA_256, SHA_3
from feistel.utils import hash


class TestFPECipher(TestCase):
    def test_encrypt(self):
        expected = Readable("K¡(#q|r5*")
        cipher = FPECipher(
            SHA_256,
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
            10,
        )
        found = cipher.encrypt("Edgewhere")
        self.assertEqual(found, expected)

    def test_encrypt_number(self):
        expected = 22780178
        cipher = FPECipher(SHA_256, "some-32-byte-long-key-to-be-safe", 128)
        found = cipher.encrypt_number(123456789)
        self.assertEqual(found, expected)

        smallNumber = cipher.encrypt_number(123)
        self.assertEqual(smallNumber, 24359)

        # Different size of numbers
        for test in [100, 1403, 100000, 50000000]:
            obfuscated = cipher.encrypt_number(test)
            deciphered = cipher.decrypt_number(obfuscated)
            self.assertEqual(deciphered, test)

        zero = cipher.encrypt_number(0)
        self.assertEqual(zero, 0)

        veryLargeNumber = cipher.encrypt_number(
            18446744073709551615
        )  # Max 64-bit unsigned int in Python and uint64 in Golang
        self.assertEqual(veryLargeNumber, 17630367666640955566)

    def test_decrypt(self):
        nonFPE = (
            "\u0002Edgewhere"  # leading U+0002: padding byte of the non-FPE `Cipher`
        )
        cipher = FPECipher(
            SHA_256,
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
            10,
        )
        found = cipher.decrypt(hex2Readable("3d7c0a0f51415a521054"))
        self.assertEqual(found, nonFPE)

        expected = "Edgewhere"
        found = cipher.decrypt(hex2Readable("2a5d07024f5a501409"))
        self.assertEqual(found, expected)

        found = cipher.decrypt(Readable("K¡(#q|r5*"))
        self.assertEqual(found, expected)

        fromBlake2 = Readable("¼u*$q0up¢")
        cipher = FPECipher(
            BLAKE2B,
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
            10,
        )
        blake2 = cipher.decrypt(fromBlake2)
        self.assertEqual(blake2, expected)

    def test_decrypt_number(self):
        expected = 123456789
        cipher = FPECipher(SHA_256, "some-32-byte-long-key-to-be-safe", 128)
        found = cipher.decrypt_number(22780178)
        self.assertEqual(found, expected)

        smallNumber = cipher.decrypt_number(24359)
        self.assertEqual(smallNumber, 123)

        zero = cipher.decrypt_number(0)
        self.assertEqual(zero, 0)

        veryLargeNumber = cipher.decrypt_number(17630367666640955566)
        self.assertEqual(veryLargeNumber, 18446744073709551615)

    def test_decrypt_string(self):
        expected = "Edgewhere"
        input = "K¡(#q|r5*"
        cipher = FPECipher(
            SHA_256,
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
            10,
        )
        deobfuscated = cipher.decrypt_string(input)
        self.assertEqual(deobfuscated, expected)
        self.assertTrue(len(deobfuscated) == len(input))

    def test_number_as_string(self):
        input = "00123"
        output = "24359"
        cipher = FPECipher(SHA_256, "some-32-byte-long-key-to-be-safe", 128)
        obfuscated = cipher.encrypt_number_as_string(input)
        self.assertEqual(obfuscated, output)

        deobfuscated = cipher.decrypt_number_as_string(output)
        self.assertEqual(deobfuscated, input)


class TestFPERoundTrip(TestCase):
    """
    Non-regression tests for the lossy `decrypt()` of v1.0.1: whenever the last round happened to
    end on a null byte, one character was dropped from the deciphered result (~1% of the couples).
    """

    def test_decrypt_does_not_drop_a_character(self):
        # Minimal reproducible case: 'ef' used to be deciphered as 'f'
        key = hash(bytearray.fromhex("a" * 64)).hex()
        cipher = FPECipher(SHA_256, key, 10)
        obfuscated = cipher.encrypt("ef")
        self.assertEqual(len(obfuscated), 2)
        self.assertEqual(cipher.decrypt(obfuscated), "ef")

    def test_roundtrip_on_a_large_random_sample(self):
        alphabets = [
            string.ascii_letters + string.digits + " .-_@",  # ASCII
            "éèêàùçôöüñÿÉÀÇ€£¥§°",  # Latin-1 supplement (2-byte UTF-8)
            string.ascii_lowercase + "éàç€漢字日本語🎉🙂",  # mixed, up to 4-byte UTF-8
        ]
        rng = random.Random(20260906)  # seeded: failures are reproducible
        for _ in range(5000):
            key = hash(bytearray(rng.getrandbits(8) for _ in range(32))).hex()
            rounds = rng.choice([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 20, 33, 128])
            engine = rng.choice([SHA_256, BLAKE2B, KECCAK, SHA_3])
            cipher = FPECipher(engine, key, rounds)
            alphabet = rng.choice(alphabets)
            data = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 80)))

            obfuscated = cipher.encrypt(data)
            # Encryption is format-preserving: as many characters out as bytes in
            self.assertEqual(
                len(obfuscated),
                len(data.encode("utf-8")),
                msg=f"length not preserved for {data!r} (engine={engine}, rounds={rounds}, key={key})",
            )
            self.assertEqual(
                cipher.decrypt(obfuscated),
                data,
                msg=f"round-trip failed for {data!r} (engine={engine}, rounds={rounds}, key={key})",
            )
