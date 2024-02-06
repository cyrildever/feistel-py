import math
from feistel.utils.base256 import Readable, readable2bytearray, to_base256_readable
from feistel.utils.bytearray import add_bytes, bytearray2ints, split_bytes
from feistel.utils.hash import Engine, H, is_available_engine
from feistel.utils.strings import add, extract, split, string2bytearray
from feistel.utils.xor import NEUTRAL, NEUTRAL_BYTES, xor, xor_bytes


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

    def encrypt_number(self, n: int) -> int:
        """
        Obfuscate numbers
        """
        if n < 128:
            if n == 0:
                return 0
            b = n.to_bytes(2, "big")
            string = b.decode()
            return int.from_bytes(readable2bytearray(self.encrypt(string)), "big")

        bits = 8 if math.ceil(math.log2(n) / 8) > 4 else 4
        buf = n.to_bytes(bits, "big")
        parts = split_bytes(buf)
        # Apply the FPE Feistel cipher
        for i in range(0, self.rounds):
            left = parts[1]
            if len(parts[1]) < len(parts[0]):
                parts[1].extend(NEUTRAL_BYTES)
            rnd = self._round_bytes(parts[1], i)
            tmp = parts[0]
            crop = False
            if len(tmp) + 1 == len(rnd):
                tmp.extend(NEUTRAL_BYTES)
                crop = True
            right = xor_bytes(tmp, rnd)
            if crop:
                right = right[: len(right) - 1]
            parts = [left, right]

        b = parts[0] + parts[1]
        return int.from_bytes(b, "big")

    def encrypt_string(self, string: str) -> Readable:
        """
        Obfuscate strings
        """
        return self.encrypt(string)

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

    def decrypt_number(self, obfuscated: int) -> int:
        """
        Deobfuscate numbers
        """
        if obfuscated == 0:
            return 0
        size = math.ceil(math.log2(obfuscated) / 8)
        if size > 4:
            buf = obfuscated.to_bytes(8, "big")
        elif size > 2:
            buf = obfuscated.to_bytes(4, "big")
        else:
            buf = obfuscated.to_bytes(2, "big")

        # Apply FPE Feistel cipher
        left, right = split_bytes(buf)
        if self.rounds % 2 != 0 and len(left) != len(right):
            left.extend([right[0]])
            right = right[1:]
        for i in range(0, self.rounds):
            leftRound = left
            if len(left) < len(right):
                leftRound.extend(NEUTRAL_BYTES)
            rnd = self._round_bytes(leftRound, self.rounds - i - 1)
            rightRound = right
            extended = False
            if len(rightRound) + 1 == len(rnd):
                rightRound.extend(left[len(left) - 1])
                extended = True
            tmp = xor_bytes(rightRound, rnd)
            right = left
            if extended:
                tmp = tmp[: len(tmp) - 1]
            left = tmp

        b = left + right
        return int.from_bytes(b, "big")

    def _round(self, item: str, idx: int) -> str:
        addition = add(item, extract(self.key, idx, len(item)))
        hex_hashed = H(string2bytearray(addition), self.engine).hex()
        return extract(hex_hashed, idx, len(item))

    def _round_bytes(self, item: bytearray, idx: int) -> bytearray:
        addition = add_bytes(item, string2bytearray(extract(self.key, idx, len(item))))
        hashed = H(addition, self.engine)
        extracted = extract(hashed.hex(), idx, len(item))
        return string2bytearray(extracted)
