from feistel.utils.base256 import Readable, readable2bytearray, to_base256_readable
from feistel.utils.hash import Engine, H, is_available_engine
from feistel.utils.strings import add, extract, split, string2bytearray
from feistel.utils.xor import NEUTRAL, xor


class FPECipher:
    def __init__(self, engine: Engine, key: str, rounds: int):
        """
        The FPECipher class is the latest entry point to the Feistel cipher lib providing full Format-Preserving Encryption.
        It makes use of one of the four hash algorithm added to the library (Blake-2b, Keccak, SHA-256 and SHA-3) to hash
        messages using the passed base key and at least 2 rounds.
        For optimal security, use a 256-bits key. And 10 rounds is a good start.
        Once instantiated, use the `encrypt()` or `decrypt()` methods on the `FPECipher` instance with the appropriate data.
        """
        assert (
            is_available_engine(engine) and key and rounds >= 2
        ), "FPECipherError: wrong arguments"
        self.engine = engine
        # self.key = "".join([chr(x) for x in bytearray.fromhex(key)])
        self.key = key
        self.rounds = rounds

    def encrypt(self, data: str) -> Readable:
        """
        Obfuscate the passed data
        """
        if len(data) == 0:
            return Readable("")

        # Apply the FPE Feistel cipher
        parts = split(data)
        for i in range(0, self.rounds):
            left = parts[1]
            if len(parts[1]) < len(parts[0]):
                parts[1] += NEUTRAL
            rnd = self._round(parts[1], i)
            tmp = parts[0]
            crop = False
            if len(tmp) + 1 == len(rnd):
                tmp += NEUTRAL
                crop = True
            right = xor(tmp, rnd)
            if crop:
                right = right[: len(right) - 1]
            parts = [left, right]

        return to_base256_readable(string2bytearray("".join(parts)))

    def decrypt(self, obfuscated: Readable) -> str:
        """
        Deobfuscate the passed data
        """
        if len(obfuscated) == 0:
            return ""

        # Apply the FPE Feistel cipher
        left, right = split(readable2bytearray(obfuscated).decode("utf-8"))
        if self.rounds % 2 != 0 and len(left) != len(right):
            left += right[:1]
            right = right[1:]

        for i in range(0, self.rounds):
            leftRound = left
            if len(left) < len(right):
                leftRound += NEUTRAL
            rnd = self._round(leftRound, self.rounds - i - 1)
            rightRound = right
            extended = False
            if len(rightRound) + 1 == len(rnd):
                rightRound += left[len(left) - 1 :]
                extended = True
            tmp = xor(rightRound, rnd)
            right = left
            if extended:
                tmp = tmp[0 : len(tmp) - 1]
            left = tmp

        return left + right

    def _round(self, item: str, idx: int) -> str:
        addition = add(item, extract(self.key, idx, len(item)))
        hex_hashed = H(string2bytearray(addition), self.engine).hex()
        return extract(hex_hashed, idx, len(item))
