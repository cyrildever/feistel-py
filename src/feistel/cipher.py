from feistel.utils.hash import hash
from feistel.utils.padding import pad, unpad
from feistel.utils.strings import add, extract, split, string2bytearray
from feistel.utils.xor import xor


class Cipher:
    def __init__(self, key: str, rounds: int):
        """
        The Cipher class is the main entry point to the Feistel cipher if you want to use the SHA-256 hash function at each round.
        You should instantiate it with the base key you want to use and the number of rounds to apply.
        For better security, you should choose a 256-bit key or longer, and 10 rounds is a good start.
        Once instantiated, use the encrypt() or decrypt() methods on the Cipher instance with the appropriate data.
        """
        assert key and rounds >= 2, "CipherError: wrong arguments"
        self.key = key
        self.rounds = rounds

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
        for i in range(0, self.rounds):
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
        for i in range(0, self.rounds):
            tmp = xor(a, self._round(b, self.rounds - i - 1))
            a = b
            b = tmp

        return unpad(b + a)

    def _round(self, item: str, idx: int) -> str:
        addition = add(item, extract(self.key, idx, len(item)))
        hex_hashed = hash(string2bytearray(addition)).hex()
        return extract(hex_hashed, idx, len(item))
