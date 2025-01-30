"""
https://cryptopals.com/sets/1
"""
from string import hexdigits

def xor(hex_string1: str, hex_string2: str) -> str:
    """
    Given two hex strings. Perform XOR operations
    """
    assert all(c in hexdigits for c in hex_string1)
    assert all(c in hexdigits for c in hex_string2)
    # 1. Convert hex strings to integers, then perform XOR
    # a = int(hex_string1, 16)
    # b = int(hex_string2, 16)
    # res = hex(a ^ b)
    # 2. Convert hex strings to byte strings, then perform XOR byte-by-byte
    byte_string1 = bytes.fromhex(hex_string1)    
    byte_string2 = bytes.fromhex(hex_string2)
    return bytes([int(x) ^ int(y) for x, y in zip(byte_string1, byte_string2)]) 

if __name__ == '__main__':
    h1 = '1c0111001f010100061a024b53535009181c'
    h2 = '686974207468652062756c6c277320657965'
    print("XOR two hex strings:", xor(h1, h2).decode())