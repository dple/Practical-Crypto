import os 

def bits_pad(num, bytes_length):
    num_padded = format(num, 'b')
    print("Number before being padded:", num_padded)
    if len(num_padded) > bytes_length * 8:
        raise ValueError("Message to long for given size")
    
    bits_padded = bytes_length * 8 - len(num_padded)
    num_padded += format(1 << bits_padded, 'b')
    print("Padded number (binary):", num_padded)

    return int(num_padded, 2)   # convert number to decimal

'''
ISO/IEC 7816-4 padding, ISO/IEC 7816-4 itself is a communication standard for smart cards 
containing a file system, and in itself does not contain any cryptographic specifications.

Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
        ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
'''
def iso_7816_4_pad(message, block_size):
    message_bytes = message.encode('utf-8')
    padding_length = block_size - (len(message_bytes) % block_size)
    padding_message = [0] * (padding_length - 1)    

    return message_bytes + b'\x80' + bytes(padding_message)

def iso_7816_4_unpad(padded_message, block_size):
    if len(padded_message) % block_size != 0:
        raise ValueError("Invalid ISO/IEC 7816-4 padding")

    index = padded_message.find(b'\x80', len(padded_message) - block_size)
    return padded_message[:index]



'''
In ANSI X9.23, between 1 and 8 bytes are always added as padding. The block is padded with random bytes 
(although many implementations use 00) and the last byte of the block is set to the number of bytes added.

ANSI X9 padding is used in block cipher in CBC mode to make a plaintext multiple of the block size, e.g., multiple of 8 bytes (64 bits) 
'''
def ANXI_X9_23_pad(message, block_size):
    message_bytes = message.encode('utf-8')
    padding_length = block_size - (len(message_bytes) % block_size)    
    # 1. Pad with 00 
    '''
    padded_message = [0 for _ in range(padded_length - 1)]
    padded_message.append(padded_length)
    return message_bytes + bytes(padded_message)
    '''
    # Pad with random bytes 
    padding_message = os.urandom(padding_length - 1)        
    return message_bytes + padding_message + bytes([padding_length])


def ANXI_X9_23_unpad(padded_message, block_size):
    if len(padded_message) % block_size != 0:
        raise ValueError("Invalid ANSI X9.23 padding")
    
    padding_length = padded_message[-1]
    return padded_message[:(len(padded_message) - padding_length)]

'''
PKCS#1 v1.5 padding: used to pad short message in RSA cryptosystem 
Format: 
    padded message: b"\x00\x02" + b"random bytes" + b"\x00" + message_bytes
'''
def pkcs1_v1_5_pad(message, key_size):
    message_bytes = message.encode('utf-8')
    max_message_length = (key_size // 8) - 11   # 11 is length of padding overhead

    if len(message_bytes) > max_message_length:
        raise ValueError("Message to long for given size")
    
    padding_length = max_message_length - len(message_bytes)

    padding_message = os.urandom(padding_length)

    return b'\x00\x02' + padding_message.replace(b'\x00', b'\x01') + b'\x00' + message_bytes

def pkcs1_v1_5_unpad(padded_message):
    # Check if the padded message is a valid format
    index = padded_message.find(b'\x00', 2)     # look up the byte b'\x00' starting from the 2nd byte 
    if (not padded_message.startswith(b"\x00\x02")) or (index == -1):
        print("Index = ", index)
        print("Padded message:", padded_message)
        raise ValueError("Invalid PCKS#1 v1.5 padding.")       
    
    return padded_message[index + 1:]


'''
The value of each added byte is the number of bytes that are added, i.e. N bytes, each of value N are added
- 4 bytes added as the below example:
    ... | DD DD DD DD DD DD DD DD | DD DD DD DD 04 04 04 04 |
'''
def pkcs7_pad(message, block_size):
    message_bytes = message.encode('utf-8')
    padding_length = block_size - (len(message_bytes) % block_size)    
    if padding_length == 0:
        padding_length = block_size
    
    return message_bytes + bytes([padding_length] * padding_length)
    


def pkcs7_unpad(padded_message, block_size):
    if len(padded_message) % block_size != 0:
        raise ValueError("Invalid PKCS#7 padding.")
     
    padding_length = padded_message[-1]
    assert padding_length > 0
    pad = padded_message[-padding_length:]
    assert all(x == padding_length for x in pad)

    return padded_message[:-padding_length]


'''
PKCS# v2 or OAEP padding replaces PKCS#1 v1.5 to avoid Bleichenbacker adaptively chosen ciphertext attack against RSA encryption.

'''
def pkcs1_v2_pad(message, key_size):
    pass 

def pkcs1_v2_unpad(padded_message):
    pass 


'''
PKCS# v2.1 or PSS padding replaces PKCS#1 v1.5 to avoid Bleichenbacker adaptively chosen ciphertext attack against RSA signing.

'''
def pkcs1_v2_1_pad(message, key_size):
    pass 

def pkcs1_v2_1_unpad(padded_message):
    pass 


if __name__ == '__main__':
    txt = "My name is Ståle"
    n = 3452
    print("Padded number (decimal):", bits_pad(n, 3))
    print()

    anxi_padded_message = ANXI_X9_23_pad(txt, 8)
    print("Padded ANXI X9.23 message:", anxi_padded_message)
    print("Unpaded ANXI X9.23 message:", ANXI_X9_23_unpad(anxi_padded_message, 8))
    print()

    iso7816_padded_message = iso_7816_4_pad(txt, 8)
    print("Padded ISO 7816_4 message:", iso7816_padded_message)
    print("Unpaded ISO 7816_4 message:", iso_7816_4_unpad(iso7816_padded_message, 8))
    print()

    pkcs1_v1_5__padded_message = pkcs1_v1_5_pad(txt, 2048)
    print("Padded PKCS#1 v1.5 message:", pkcs1_v1_5__padded_message)
    print("Unpaded PKCS#1 v1.5 message:", pkcs1_v1_5_unpad(pkcs1_v1_5__padded_message))
    print()

    pkcs7_padded_message = pkcs7_pad(txt, 8)
    print("Padded PKCS#7 message:", pkcs7_padded_message)
    print("Unpaded PKCS#7 message:", pkcs7_unpad(anxi_padded_message, 8))
    print()