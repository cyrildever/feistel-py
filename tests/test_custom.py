from unittest import TestCase

from src.feistel.custom import CustomCipher


class TestCustomCipher(TestCase):
    def test_encrypt(self):
        expected = "3d7c0a0f51415a521054"
        cipher = CustomCipher(
            [
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
                "8ed9dcc1701c064f0fd7ae235f15143f989920e0ee9658bb7882c8d7d5f05692",
            ]
        )
        found = cipher.encrypt("Edgewhere").hex()
        self.assertEqual(found, expected)

        expected = "445951465c5a19613633"
        cipher = CustomCipher(
            [
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            ]
        )
        found = cipher.encrypt("Edgewhere").hex()
        self.assertEqual(found, expected)

    def test_decrypt(self):
        expected = "Edgewhere"
        cipher = CustomCipher(
            [
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            ]
        )
        obfuscated = bytearray.fromhex("445951465c5a19613633")
        found = cipher.decrypt(obfuscated)
        self.assertEqual(found, expected)
