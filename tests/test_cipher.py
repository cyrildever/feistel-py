from unittest import TestCase

from src.feistel.cipher import Cipher


class TestCipher(TestCase):
    def test_encrypt(self):
        expected = "3d7c0a0f51415a521054"
        cipher = Cipher(
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692", 10
        )
        found = cipher.encrypt("Edgewhere").hex()
        self.assertEqual(found, expected)

    def test_decrypt(self):
        expected = "Edgewhere"
        cipher = Cipher(
            "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692", 10
        )
        obfuscated = bytearray.fromhex("3d7c0a0f51415a521054")
        found = cipher.decrypt(obfuscated)
        self.assertEqual(found, expected)

        obfuscated = b"=|\n\x0fQAZR\x10T"
        found = cipher.decrypt(obfuscated)
        self.assertEqual(found, expected)
