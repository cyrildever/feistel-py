NEUTRAL = bytearray([0])


def xor(str1: str, str2: str) -> str:
    """
    Applies XOR operation on two strings in the sense that each charCode are xored
    """
    return "".join([chr(ord(c) ^ ord(str2[idx])) for idx, c in enumerate(str1)])
