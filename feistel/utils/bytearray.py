from pyutls.list import flatten


def add_bytes(b1: bytearray, b2: bytearray) -> bytearray:
    """
    Adds two byte arrays in the sense that each bit values are added modulo 256 to be rendered as UTF-8
    """
    assert len(b1) == len(
        b2
    ), "Error: to be added, byte arrays must be of the same length"

    bytes1 = bytearray2ints(b1)
    bytes2 = bytearray2ints(b2)

    arr = list[list[int]]()
    for p1, p2 in zip(bytes1, bytes2):
        arr.append(_value2utf8ints((p1 + p2) % 256))

    return bytearray(flatten(arr))


def bytearray2ints(b: bytearray) -> list[int]:
    """
    Returns the array of integer values of the passed byte array
    """
    return [x for x in b]


def split_bytes(b: bytearray) -> tuple[bytearray, bytearray]:
    """
    Splits a byte array in two parts
    """
    half = int(len(b) / 2)
    return [b[:half], b[half:]]


# Utility to mimic transformation of byte array to UTF-8 in Golang
def _value2utf8ints(value: int) -> list[int]:
    if value < 128:
        return [value]
    elif value < 192:
        return [194, value]
    else:
        return [195, value - 64]
