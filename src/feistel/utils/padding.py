# Unicde U+0002: start-of-text
PADDING_CHARACTER = "\u0002"


def pad(data: str) -> str:
    if len(data) % 2 == 0:
        return data
    return PADDING_CHARACTER + data


def unpad(data: str) -> str:
    while data.startswith(PADDING_CHARACTER):
        data = data[1:]
    return data
