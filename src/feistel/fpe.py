import math


from feistel.utils import (
    add,
    add_bytes,
    Engine,
    extract,
    H,
    is_available_engine,
    NEUTRAL_BYTES,
    Readable,
    readable2bytearray,
    split_bytes,
    string2bytearray,
    to_base256_readable,
    xor_bytes,
)


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

        b = self.encrypt_bytes(bytearray(data, "utf-8"))

        return to_base256_readable(b)

    def encrypt_bytes(self, bytes: bytearray) -> bytearray:
        """
        Obfuscate bytes

        NB: The returned byte array should be made readable if need be
        """
        parts = split_bytes(bytes)

        # Apply the FPE Feistel cipher
        for i in range(0, self.rounds):
            left = parts[1].copy()
            if len(parts[1]) < len(parts[0]):
                parts[1].extend(NEUTRAL_BYTES)
            rnd = self._round_bytes(parts[1], i)
            tmp = parts[0].copy()
            crop = False
            if len(tmp) + 1 == len(rnd):
                tmp.extend(NEUTRAL_BYTES)
                crop = True
            right = xor_bytes(tmp, rnd)
            if crop:
                right = right[: len(right) - 1]
            parts = [left, right]

        return parts[0] + parts[1]

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

        size = math.ceil(math.log2(n) / 8)
        bits = 8 if size > 4 else 4 if size > 2 else size
        buf = n.to_bytes(bits, "big")

        b = self.encrypt_bytes(bytearray(buf))

        return int.from_bytes(b, "big")

    def encrypt_number_as_string(self, n: str) -> str:
        """
        Obfuscate numbers passed and returned as string to maintain the number of characters
        """
        obfuscated = self.encrypt_number(int(n))
        return str(obfuscated).zfill(len(n))

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

        b = self.decrypt_bytes(readable2bytearray(obfuscated))

        return b.decode("utf-8")

    def decrypt_bytes(self, bytes: bytearray) -> bytearray:
        """
        Deobufscate bytes

        NB: The returned byte array should be cast into a UTF-8 string or an integer if need be
        """
        # Apply FPE Feistel cipher
        left, right = split_bytes(bytes)
        if self.rounds % 2 != 0 and len(left) != len(right):
            left.extend([right[0]])
            right = right[1:].copy()
        for i in range(0, self.rounds):
            leftRound = left.copy()
            if len(left) < len(right):
                leftRound.extend(NEUTRAL_BYTES)
            rnd = self._round_bytes(leftRound, self.rounds - i - 1)
            rightRound = right.copy()
            extended = False
            if len(rightRound) + 1 == len(rnd):
                rightRound.extend([left[len(left) - 1]])
                extended = True
            if i == self.rounds - 1 and rightRound[len(rightRound) - 1] == 0:
                extended = True
            tmp = xor_bytes(rightRound, rnd)
            right = left.copy()
            if extended:
                tmp = tmp[: len(tmp) - 1]
            left = tmp.copy()

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

        b = self.decrypt_bytes(bytearray(buf))

        return int.from_bytes(b, "big")

    def decrypt_number_as_string(self, n: str) -> str:
        """
        Deobfuscate numbers passed and returned as string to maintain the number of characters
        """
        deobfuscated = self.decrypt_number(int(n))
        return str(deobfuscated).zfill(len(n))

    def decrypt_string(self, obfuscated: str) -> str:
        """
        Deobfuscate strings
        """
        return self.decrypt(Readable(obfuscated))

    # private methods

    def _round(self, item: str, idx: int) -> str:
        addition = add(item, extract(self.key, idx, len(item)))
        hex_hashed = H(string2bytearray(addition), self.engine).hex()
        return extract(hex_hashed, idx, len(item))

    def _round_bytes(self, item: bytearray, idx: int) -> bytearray:
        addition = add_bytes(item, string2bytearray(extract(self.key, idx, len(item))))
        hashed = H(addition, self.engine)
        extracted = extract(hashed.hex(), idx, len(item))
        return string2bytearray(extracted)
