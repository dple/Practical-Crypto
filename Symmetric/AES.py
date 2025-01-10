from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from os import urandom

class AES:
    def __init__(self, keylen):
        '''
        - Key must be 128, 192 or 256 bits. Key length is provided in number of bytes --> 16, 24, 32
        - IV must be a 16 random bytes, equal to length of a AES block
        '''
        self.key = urandom(keylen)
        self.iv = urandom(16)
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def padding(self, data):        
        padder = padding.PKCS7(128).padder()    # 128 = 16 bytes of block size
        data = data.encode(encoding='utf-8')
        return padder.update(data) + padder.finalize()

    def unpadding(self, padded_data):
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def encrypt(self, plaintext):
        padded_data = self.padding(plaintext)
        encryptor = self.cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext):
        decryptor = self.cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return self.unpadding(decrypted_data).decode()

    if __name__ == '__main__':
        pass 

if __name__ == '__main__':
    message = "This is a cleartext, which is be encrypted by using AES block cipher with CBC mode"
    aes = AES(32)   # AES256 -> 32 bytes
    ct = aes.encrypt(message)
    print("Encrypted message:", ct)
    print("Decrypted message:", aes.decrypt(ct))
