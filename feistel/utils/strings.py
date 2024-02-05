def add(str1: str, str2: str) -> str:
    """
    Adds two strings in the sense that each charCode are added
    """
    if len(str1) != len(str2):
        raise Exception("to be added, strings must be of the same length")

    return "".join([chr(ord(c) + ord(str2[idx])) for idx, c in enumerate(str1)])


def extract(from_str: str, start_index: int, desired_length: int) -> str:
    """
    Returns an extraction of the passed string of the desired length from the passed start index.
    If the desired length is too long, the key string is repeated.
    """
    start_index = start_index % len(from_str)
    length_needed = start_index + desired_length
    repetitions = int(length_needed / len(from_str)) + 1
    repeated = from_str * repetitions
    return repeated[start_index : start_index + desired_length]


def split(string: str) -> list[str]:
    """
    Splits a string in two parts, the first part being one character shorter in case the passed item has odd length
    """
    half = int(len(string) / 2)
    return [string[:half], string[half:]]
