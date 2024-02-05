from feistel.utils.hash import hash
from feistel.utils.padding import pad, unpad
from feistel.utils.strings import add, extract, split, string2bytearray
from feistel.utils.xor import xor


class CustomCipher:
    def __init__(self, keys: list[str]):
        """
        The CustomCipher uses custom keys instead of the SHA-256 hashing function to provide a new key at each round.
        The number of rounds is then determined by the number of keys provided.
        NB: There must be at least two keys.
        """
        assert len(keys) >= 2, "CustomCipherError: wrong arguments"
        self.keys = keys

    def encrypt(self, data: str) -> bytearray:
        """
        Obfuscate the passed data
        """
        if len(data) == 0:
            return bytearray()

        if len(data) % 2 == 1:
            data = pad(data)

        # Apply the balanced Feistel cipher
        left, right = split(data)
        if len(left) != len(right):
            raise Exception("invalid string: unable to split")

        parts = [left, right]
        for i in range(0, len(self.keys)):
            tmp = xor(parts[0], self._round(parts[1], i))
            parts = [parts[1], tmp]

        return string2bytearray(parts[0] + parts[1])

    def decrypt(self, obfuscated: bytes | bytearray) -> str:
        """
        Deobfuscate the passed data
        """
        assert len(obfuscated) % 2 == 0, "CipherError: invalid obfuscated data"
        if len(obfuscated) == 0:
            return ""

        o = obfuscated.decode()

        # Apply the balanced Feistel cipher
        b, a = split(o)
        for i in range(0, len(self.keys)):
            tmp = xor(a, self._round(b, len(self.keys) - i - 1))
            a = b
            b = tmp

        return unpad(b + a)

    def _round(self, item: str, idx: int) -> str:
        addition = add(item, extract(self.keys[idx], idx, len(item)))
        hex_hashed = hash(string2bytearray(addition)).hex()
        return extract(hex_hashed, idx, len(item))
