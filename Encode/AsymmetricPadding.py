import os

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
    
    pkcs1_v1_5__padded_message = pkcs1_v1_5_pad(txt, 2048)
    print("Padded PKCS#1 v1.5 message:", pkcs1_v1_5__padded_message)
    print("Unpaded PKCS#1 v1.5 message:", pkcs1_v1_5_unpad(pkcs1_v1_5__padded_message).decode())
    print()
