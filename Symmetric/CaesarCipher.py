"""
In Caesar cipher, each letter in the plaintext will be rotation-shifted by an integer k.
For example: if k = 3, then 'a' -> 'd'
"""

class CaesarCipher:
    lower = 'abcdefghijklmnopqrstuvwxyz' 
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    cipher_in = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz '
    cipher_out = 'XYZABCDEFGHIJKLMNOPQRSTUVWxyzabcdefghijklmnopqrstuvw '    

    def __init__(self, k):
        self.k = k
    
    def encrypt(self, plaintext):
        res = ''
        for c in plaintext:
            if c in self.lower:
                res += self.lower[(self.lower.index(c) + self.k) % 26]
            elif c in self.upper:
                res += self.upper[(self.upper.index(c) + self.k) % 26]
            else:
                res += c
        return res 
    
    
    def decrypt(self, cipher):
        res = ''
        for c in cipher:
            if c in self.lower:
                res += self.lower[(self.lower.index(c) - self.k) % 26] 
            elif c in self.upper:
                res += self.upper[(self.upper.index(c) - self.k) % 26]
            else:
                res += c
        return res
    
    def cipher(self, plaintext):
        # Using map, built-in functional function in Python
        return ''.join(map(lambda x: self.cipher_out[self.cipher_in.index(x)], plaintext))
    
    def decipher(self, ciphertext):
        # Using map, built-in functional function in Python
        return ''.join(map(lambda x: self.cipher_in[self.cipher_out.index(x)], ciphertext))


if __name__ == '__main__':
    caesar = CaesarCipher(-4)
    plaintext = "The is a clear text"
    ciphertext = caesar.cipher(plaintext)  # caesar.encrypt(plaintext)
    print("Encrypted message:", ciphertext)
    decrypted = caesar.decipher(ciphertext)  # caesar.decrypt(ciphertext)
    print("Decrypted message:", decrypted)