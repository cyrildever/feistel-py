import hashlib
from Crypto.Hash import keccak


def hash(input: bytearray) -> bytearray:
    h = hashlib.sha256()
    h.update(input)
    return h.digest()


# Engine
Engine = str
BLAKE2B = Engine("blake-2b-256")
KECCAK = Engine("keccak-256")
SHA_256 = Engine("sha-256")
SHA_3 = Engine("sha-3")


def is_available_engine(engine: Engine) -> bool:
    return engine == BLAKE2B or engine == KECCAK or engine == SHA_256 or engine == SHA_3


def H(msg: bytearray, using: Engine) -> bytearray:
    """
    Create a hash from the passed message using the specified algorithm
    """
    if using == BLAKE2B:
        b2b = hashlib.blake2b(digest_size=32)
        b2b.update(msg)
        return b2b.digest()
    elif using == KECCAK:
        k = keccak.new(digest_bits=256)
        k.update(msg)
        return k.digest()
    elif using == SHA_256:
        return hash(msg)
    elif using == SHA_3:
        s3 = hashlib.sha3_256()
        s3.update(msg)
        return s3.digest()
    else:
        raise Exception("unknown hash algorithm")
