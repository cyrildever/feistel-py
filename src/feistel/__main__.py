import argparse
import ast
import sys

from feistel.cipher import Cipher
from feistel.custom import CustomCipher
from feistel.fpe import Engine, FPECipher
from feistel.utils.hash import SHA_256, is_available_engine

CUSTOM = "custom"
FEISTEL = "feistel"
FPE = "fpe"


def main(args):
    if not args.input or not args.operation:
        raise Exception("Missing mandatory parameters")
    data = str(args.input)
    operation = str(args.operation)
    if operation != "cipher" and operation != "decipher":
        raise Exception("Invalid operation")

    cipher_type = (
        args.cipher
        if args.cipher and args.cipher in [FEISTEL, CUSTOM, FPE]
        else FEISTEL
    )
    if cipher_type == FEISTEL:
        if operation == "decipher" and data.startswith("b'") and data.endswith("'"):
            data = ast.literal_eval(args.input)
        key = str(args.key)
        if not key:
            raise Exception("missing mandatory key")
        rounds = int(args.rounds) if args.rounds else 10
        cipher = Cipher(key, rounds)
    elif cipher_type == CUSTOM:
        if operation == "decipher" and data.startswith("b'") and data.endswith("'"):
            data = ast.literal_eval(args.input)
        keys = str(args.key).split(",")
        if len(keys) == 0:
            raise Exception("missing mandatory keys")
        cipher = CustomCipher(keys)
    else:
        key = str(args.key)
        if not key:
            raise Exception("missing mandatory key")
        if not is_available_engine(args.engine):
            engine = SHA_256
        else:
            engine = Engine(args.engine)
        rounds = int(args.rounds) if args.rounds else 10
        cipher = FPECipher(engine, key, rounds)

    if operation == "cipher":
        print(cipher.encrypt(data))
    else:
        print(cipher.decrypt(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="The string to obfuscate (watch for quotes)")
    parser.add_argument(
        "-c", "--cipher", help="The type of cipher: feistel [default] | custom | fpe"
    )
    parser.add_argument("-e", "--engine", help="The hashing engine [default sha-256]")
    parser.add_argument("-k", "--key", help="The key(s) to use")
    parser.add_argument(
        "-r", "--rounds", help="The (optional) number of rounds [default 10]"
    )
    parser.add_argument(
        "-o", "--operation", help="The operation to process : cipher | decipher"
    )
    args = parser.parse_args()

    main(args)
