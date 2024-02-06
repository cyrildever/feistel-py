from unittest import TestCase

from src.feistel.fpe import FPECipher
from src.feistel.utils.base256 import Readable, hex2Readable
from src.feistel.utils.hash import BLAKE2B, SHA_256


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

        zero = cipher.encrypt_number(0)
        self.assertEqual(zero, 0)

        veryLargeNumber = cipher.encrypt_number(
            18446744073709551615
        )  # Max 64-bit unsigned int in Python and uint64 in Golang
        self.assertEqual(veryLargeNumber, 17630367666640955566)

    def test_decrypt(self):
        nonFPE = "Edgewhere"
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
