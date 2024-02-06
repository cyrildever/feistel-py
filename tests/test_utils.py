from unittest import TestCase


from src.feistel.utils.base256 import (
    base256_char_at,
    hex2Readable,
    index_of_base256,
    readable2bytearray,
    readable2hex,
    to_base256_readable,
)
from src.feistel.utils.hash import BLAKE2B, H, KECCAK, SHA_256, SHA_3
from src.feistel.utils.padding import pad, unpad
from src.feistel.utils.strings import add, extract, split
from src.feistel.utils.xor import xor


class TestUtilsBase259(TestCase):
    def test_base256(self):
        self.assertEqual(base256_char_at(0), "!")
        self.assertEqual(base256_char_at(255), "ǿ")
        self.assertEqual(index_of_base256("ǿ"), 255)

    def test_readable(self):
        expected = "K¡(#q|r5*"
        fpeBytes = bytearray([42, 93, 7, 2, 79, 90, 80, 20, 9])
        found = to_base256_readable(fpeBytes)
        self.assertEqual(found, expected)
        self.assertEqual(readable2bytearray(found), fpeBytes)
        self.assertEqual(readable2hex(found), "2a5d07024f5a501409")
        hex = hex2Readable("2a5d07024f5a501409")
        self.assertEqual(hex, found)


class TestUtilsHash(TestCase):
    def test_hashes(self):
        data = b"Edgewhere"
        expected = "e5ff44a9b2caa01099082dd6e9055ea5d002beea078e9251454494ccf6869b2f"
        blake2 = H(data, BLAKE2B).hex()
        self.assertEqual(blake2, expected)

        expected = "ac501ee78bc9b9429f6b923953946606b260a8de141eb253567342b678bc5f10"
        keccak = H(data, KECCAK).hex()
        self.assertEqual(keccak, expected)

        expected = "c0c77f225dd222144bc4ef79dca00ab7d955f26da2b1e0f25df81f8a7e86917c"
        sha_256 = H(data, SHA_256).hex()
        self.assertEqual(sha_256, expected)

        expected = "9d6bf5763cb18bceb7c15270ff8400ae70bf3cd71928463a30f02805d913409d"
        sha_3 = H(data, SHA_3).hex()
        self.assertEqual(sha_3, expected)


class TestUtilsStrings(TestCase):
    def test_add(self):
        ref = "ÄÆ"
        ab = "ab"
        cd = "cd"
        found = add(ab, cd)
        self.assertEqual(found, ref)

    def test_extract(self):
        ref = "s is a testThis is a tes"
        found = extract("This is a test", 3, 24)
        self.assertEqual(found, ref)

    def test_split(self):
        left = "edge"
        right = "where"
        edgewhere = left + right
        leftPart, rightPart = split(edgewhere)
        self.assertEqual(leftPart, left)
        self.assertEqual(rightPart, right)
        self.assertTrue(len(leftPart) != len(rightPart))
        self.assertTrue(len(leftPart) + len(rightPart) == len(edgewhere))

        balanced = "balanced"
        leftPart, rightPart = split(balanced)
        self.assertEqual(leftPart, "bala")
        self.assertEqual(rightPart, "nced")
        self.assertTrue(len(balanced) % 2 == 0)
        self.assertTrue(len(leftPart) == len(rightPart))


class TestUtilsPadding(TestCase):
    def test_padding(self):
        expected = "Edgewhere"
        padded = pad(expected)
        self.assertEqual(len(padded), len(expected) + 1)
        self.assertTrue(len(padded) % 2 == 0)
        self.assertEqual(padded, "Edgewhere")
        found = unpad(padded)
        self.assertEqual(found, expected)


class TestUtilsXOR(TestCase):
    def test_xor(self):
        expected = "PPPP"
        found = xor("1234", "abcd")
        self.assertEqual(found, expected)
