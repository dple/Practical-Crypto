"""
In Caesar cipher, each letter in the plaintext will be rotation-shifted by an integer k.
For example: if k = 3, then 'a' -> 'd'
"""

class CaesarCipher:
    lower = 'abcdefghijklmnopqrstuvwxyz' 
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

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
    

if __name__ == '__main__':
    caesar = CaesarCipher(-4)
    plaintext = "The is a clear text"
    ciphertext = caesar.encrypt(plaintext)
    print("Encrypted message:", ciphertext)
    decrypted = caesar.decrypt(ciphertext)
    print("Decrypted message:", decrypted)