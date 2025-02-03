from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os 


if __name__ == '__main__':
    plaintext = b'Secret message that will be encrypted and authenticated by using ChaCha20Poly1305 authenticated encryption'   # data in bytes encrypted
    nonce = os.urandom(12)          # nonce (bytes-like) – A 12-byte (96-bit) value. NEVER REUSE A NONCE with a key.

    # Generate 32 bytes (256 bits) ChaCha20 key
    key = ChaCha20Poly1305.generate_key()       # a combination of the stream cipher ChaCha20 and the Poly1305 authenticator, 
                                                # that guarantees both data confidentiality and integrity (data authentication)
                                                # ChaCha20's input: a message of arbitrary length, a 256-bit key, a 32-bit initial counter, a 96-bit nonce (or IV)
                                                # Poly1305 takes 32-bytes one-time key and a message and produces 16-bytes Authentication Tag
    
    chacha = ChaCha20Poly1305(key)
    ad = b'authenticated but unencrypted associated data'
    ciphertext = chacha.encrypt(nonce=nonce, data=plaintext, associated_data=ad) 
                                            # Output a encrypted message + 16-byte authenticator tag
    
    print("Plaintext  (hex): ", plaintext.hex())
    print("Ciphertext (hex): ", ciphertext.hex())
    assert len(plaintext) + 16 == len(ciphertext)       

    decrypted_text = chacha.decrypt(nonce=nonce, data=ciphertext, associated_data=ad)

    assert plaintext == decrypted_text, "Decrypted message does not match!"
    
    print("Original message:", plaintext)
    print("Decrypted message:", decrypted_text)
    


