# Readable
Readable = str
CHARSET = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^`abcdefghijklmnopqrstuvwxyz{|}€¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷ùúûüýÿăąĊčđĕĘğħĩĭıĵķĿŀŁłňŋŏœŖřŝşŦŧũūůŲŵſƀƁƂƄƆƇƔƕƗƙƛƜƟƢƥƦƧƩƪƭƮưƱƲƵƸƺƾǀǁǂƿǬǮǵǶǹǻǿ")'


def base256_char_at(index: int) -> str:
    return CHARSET[index]


def index_of_base256(char: str) -> int:
    return CHARSET.index(char)


def to_base256_readable(item: bytearray) -> Readable:
    return "".join(map(base256_char_at, item))


def hex2Readable(hex: str) -> Readable:
    return to_base256_readable(bytearray.fromhex(hex))


def readable2bytearray(readable: Readable) -> bytearray:
    return bytearray(list(map(index_of_base256, readable)))


def readable2hex(readable: Readable) -> str:
    return readable2bytearray(readable).hex()
