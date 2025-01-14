from string import hexdigits
from base64 import b64decode, b64encode
"""
Given a ASCII hex string. Output a Base64 bytes-like ASCII string 
"""
def hex2base64(hex_string: str) -> str: 
    assert all(c in hexdigits for c in hex_string)
    # Convert a ASCII hex string to bytes 
    hex_bytes = bytes.fromhex(hex_string)
    # Then, encode hex bytes to Base64. Return encoded bytes 
    b64_bytes = b64encode(hex_bytes)
    # Decode Base64 encoded bytes-like object to ASCII string 
    b64_string = b64_bytes.decode()
    return b64_string

"""
Given a Base64 bytes-like ASCII string. Output a ASCII hex string
"""
def base642hex(base64_string: str) -> str:
    # Encode ASCII string to a Base64 bytes-like object
    encoded_data = base64_string.encode()
    # Decode Base64 bytes-like object to decoded bytes
    hex_bytes = b64decode(encoded_data)
    # Convert bytes-like hex to hex string 
    hex_string = hex_bytes.hex()
    return hex_string

if __name__ == '__main__':
    hex_intput = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64 = hex2base64(hex_intput)
    print("Based64 string: ", b64)
    hex_output = base642hex(b64)
    print("Hex output:", hex_output)
    assert hex_output == hex_intput
