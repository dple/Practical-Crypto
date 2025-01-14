def single_byte_xor_cipher(plaintext: bytes, key: int) -> bytes:
    """
    Given a plaintext. Single byte XOR cipher encypts the message by XOR each byte of plaintext with the One-byte key
    """    
    return bytes([byte ^ key for byte in plaintext])

if __name__ == '__main__':
    msg = b'British troops entered Cuxhaven at 1400 on 6 May - from now on all radio traffic will cease - wishing you all the best. Lt Kunkel.'
    cipher = single_byte_xor_cipher(msg, 69)
    print("Single byte XOR cipher of ", msg, "is: ", cipher)
    print("Decipher:", single_byte_xor_cipher(cipher, 69))