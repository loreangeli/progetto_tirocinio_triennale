def asciitobin (string) :
    return bin(int.from_bytes(string.encode(), 'big'))

def bintoascii (bin) :
    n = int(bin, 2)
    bin = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    return bin