# Authenticated encryption using AES with Galois Counter Mode (GCM), GCM-SIV (Synthetic IV), OCB (Offset Codebook Mode)
# AES cipher provides confidentiality
# GCM, OCB modes provides data authentication (integrity)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, AESOCB3, AESCCM, AESSIV
import os 


if __name__ == '__main__':
    plaintext = b'Secret message that will be encrypted and authenticated by using AES-GCM authenticated encryption'   # data in bytes encrypted
    ad = b'authenticated but unencrypted associated data'               # Associated date that will be authenticated, but not encrypted, for ex: network header
    nonce = os.urandom(12)              # nonce (bytes-like) – A 12-byte (96-bit) value as NIST recommendation. NEVER REUSE A NONCE with a key.

    # AESGCM mode. Generate 16 bytes (128 bits) AES key
    key = AESGCM.generate_key(bit_length=128)      
    
    aesgcm = AESGCM(key)
    
    ciphertext = aesgcm.encrypt(nonce=nonce, data=plaintext, associated_data=ad) 
                                            # Output a encrypted message + 16-byte authenticator tag
    
    print("Plaintext  (hex): ", plaintext.hex())
    print("Ciphertext (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       

    decrypted_text = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=ad)

    assert plaintext == decrypted_text, "Decrypted message does not match!"

    # AES-GCM-SIV mode (SIV = Synthetic Initialization Vector), defined in RFC 8452
    key = AESGCMSIV.generate_key(bit_length=256)        # Key could be 128, 192 or 256 bits
    aesgcmsiv = AESGCMSIV(key)

    # nonce is 12 bytes as GCM mode
    ciphertext = aesgcmsiv.encrypt(nonce=nonce, data=plaintext, associated_data=ad)     
    print("Ciphertext using AES-GCMSIV-256 (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       # 16 bytes of tag 

    decrypted_text = aesgcmsiv.decrypt(nonce=nonce, data=ciphertext, associated_data=ad)

    assert plaintext == decrypted_text

    # AES-OCB3 mode, defined in RFC 7253
    key = AESOCB3.generate_key(bit_length=128)          # Key could be 128, 192 or 256 bits
    aesocb3 = AESOCB3(key)

    ciphertext = aesocb3.encrypt(nonce=nonce, data=plaintext, associated_data=ad)       # nonce: 12-15 bytes
    print("Ciphertext using AES-OCB3 (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       

    decrypted_text = aesocb3.decrypt(nonce=nonce, data=ciphertext, associated_data=ad)

    assert plaintext == decrypted_text

    # AES-CCM mode, Counter with CBC-MAC (CCM) (specified in RFC 3610).
    key = AESCCM.generate_key(bit_length=128)               # 128, 192, or 256-bit key.
                                                            # tag lengths are 4, 6, 8, 10, 12, 14, and 16 (recommneded).
    aesccm = AESCCM(key)

    ciphertext = aesccm.encrypt(nonce=nonce, data=plaintext, associated_data=ad)    # nonce: 7 and 13 bytes
    print("Ciphertext using AES-CCM (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       

    decrypted_text = aesccm.decrypt(nonce=nonce, data=ciphertext, associated_data=ad)

    assert plaintext == decrypted_text


    # AES-SIV mode, key length must be at least 256 bit, if not 384, or 512 bit
    key = AESSIV.generate_key(bit_length=256)
    nonce = os.urandom(16)      # AES-SIV supports either deterministic encryption or probabilistic with a nonce of at least 128 bits
    aessiv = AESSIV(key)    
    ciphertext = aessiv.encrypt(data=plaintext, associated_data=[ad, nonce])
    print("Ciphertext using AES-SIV-256 (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       

    decrypted_text = aessiv.decrypt(data=ciphertext, associated_data=[ad, nonce])

    assert plaintext == decrypted_text
 

    

    print("Original message:", plaintext)
    print("Decrypted message:", decrypted_text)
    


