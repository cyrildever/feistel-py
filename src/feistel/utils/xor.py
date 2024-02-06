from feistel.utils.bytearray import bytearray2ints


NEUTRAL = bytearray([0]).decode("utf-8")
NEUTRAL_BYTES = bytearray([0])


def xor(str1: str, str2: str) -> str:
    """
    Applies XOR operation on two strings in the sense that each charCode are xored
    """
    return "".join([chr(ord(c) ^ ord(str2[idx])) for idx, c in enumerate(str1)])


def xor_bytes(b1: bytearray, b2: bytearray) -> bytearray:
    """
    Applies XOR operation on thow byte arrays in the sense that each bit value are xored
    """
    bytes1 = bytearray2ints(b1)
    bytes2 = bytearray2ints(b2)
    return bytearray([p1 ^ p2 for p1, p2 in zip(bytes1, bytes2)])
