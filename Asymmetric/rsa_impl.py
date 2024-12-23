import random 
from math import gcd
from sympy import isprime, nextprime
from padding import *

'''
Compute modular inverse a^(-1) mod n using extended Euclidean algorithm  
'''
def mod_inverse(a, n):
    n0, x0, x1 = n, 0, 1
    if gcd(a, n) != 1:
        raise ValueError("Does not exist an inverse of ", a, "modulo", n)
    
    if (n == 1):
        return 0
    
    while a > 1:
        q = a // n
        n, a = a % n, n 
        x0, x1 = x1 - q*x0, x0

    return x1 + n0 if x1 < 0 else x1

class RSACipher_Impl:
    # Public e could be 3 or 65537 (=2^16 + 1). Modulus must be at least 2048
    def __init__(self, e = 65537, modulus_length = 2048) -> None:
        self.e, self.modulus_length = e, modulus_length
        [N, d] = self.generate_keys()
        self.private_keys = [N, d]
        self.public_keys = [N, e]


    def generate_keys(self):
        '''
        Require to avoid faulty key generation: (n = modulus_length)
        - e and phi(N) must be co-primes, where phi(N) = (p - 1)(q - 1) ==> gcd(e, p - 1) = 1 and gcd(e, q - 1) = 1
        - p and q should not be too close to avoid Fermat factorization. | p - q | >= 2 N ^ {1 / 4}. 
        
        FIPS 186-4 recommends:
        - | p - q | >= 2 ^ {n / 2 - 100} (page 63), i.e., |p - q| > 2^924 for modulus length = 2048.
        - sqrt(2)(2^(n/2 - 1)) <= p, q <= 2^(n/2) - 1
        '''
        bits = self.modulus_length // 2 - 1
        safe_diff = (1 << (self.modulus_length // 2 - 100))
        p = nextprime(random.getrandbits(bits))
        
        while gcd(self.e, p - 1) != 1:
            p = nextprime(random.getrandbits(bits))

        q = nextprime(random.getrandbits(bits + 1))

        while (gcd(self.e, q - 1) != 1) or (abs(p - q) < safe_diff):
            q = nextprime(random.getrandbits(bits + 1))

        N = p * q
        phi_N = (p - 1) * (q - 1)
        lambda_N = phi_N // gcd(p - 1, q - 1)    # = lcm(p - 1, q - 1)
        d = mod_inverse(self.e, lambda_N)

        return [N, d]
    
    def get_publickeys(self):
        return self.public_keys
    
    # Encrypt a plaintext
    def encrypt(self, plaintext):
        [N, e] = self.public_keys
        msg_int = int.from_bytes(pkcs1_v1_5_pad(plaintext, self.modulus_length), byteorder='big')

        if msg_int > N:
            raise ValueError("Message is too big to encrypt.")

        cipher_int = pow(msg_int, e, N)

        return cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, byteorder='big')     # return ciphertext as an arrray of bytes
        

    def decrypt(self, ciphertext):
        N, d = self.private_keys
        # Convert ciphertext bytes to int 
        cipher_int = int.from_bytes(ciphertext, byteorder='big')
        decrypted_int = pow(cipher_int, d, N)
        padded_plaintext = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big') #.decode('utf-8', "ignore") 

        # Add one byte '\x00' to the padded plaintext as leading 0 was ignored during int operations
        return pkcs1_v1_5_unpad(b'\x00' + padded_plaintext).decode('utf-8', "ignore")


if __name__ == '__main__':
    txt = "This is RSA cryptosystem!"
    rsa = RSACipher_Impl()
    rsa.generate_keys()
    N, e = rsa.get_publickeys()
    print("Public keys:\ne = ", e, "\nN = ", N, "\n")

    ciphertext = rsa.encrypt(txt)

    print("Ciphertext: ", ciphertext, "\n")
    #print("Ciphertext: ", ciphertext.decode('utf-8', "ignore"))

    plaintext = rsa.decrypt(ciphertext)

    print("Plaintext:", plaintext)
