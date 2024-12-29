from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os 


if __name__ == '__main__':
    plaintext = b'Secret message'   # data in bytes encrypted
    nonce = os.urandom(12)          # nonce (bytes-like) – A 12 byte value. NEVER REUSE A NONCE with a key.

    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, data=plaintext, associated_data=None)
    print("Ciphertext: ", ciphertext.hex())

    decrypted_text = chacha.decrypt(nonce, data=ciphertext, associated_data=None)

    assert plaintext == decrypted_text, "Decrypted message does not match!"
    
    print("Original message:", plaintext)
    print("Decrypted message:", decrypted_text)
    


