from unittest import TestCase

from feistel.fpe import FPECipher
from feistel.utils.base256 import Readable, hex2Readable
from feistel.utils.hash import BLAKE2B, SHA_256


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
