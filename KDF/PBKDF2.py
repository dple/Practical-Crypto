"""
Password-Based Key Derivation Function (PBKDF) can be used to protect your password against brute-force atacks.
The function consists of 5 inputs DK = PBKDF2(PRF, Password, Salt, c, dkLen), where:
    - PRF is a pseudorandom function of two parameters with output length hLen (e.g., a keyed HMAC)
    - Password is the master password from which a derived key is generated
    - Salt is a sequence of bits, known as a cryptographic salt
    - c is the number of iterations desired
    - dkLen is the desired bit-length of the derived key
    - DK is the generated derived key
"""
from hashlib import pbkdf2_hmac
import os 

class SaltedPassword:
    def __init__(self, pwd, c = 1000, dkLen = 128):
        self.c = c
        self.dkLen = dkLen
        self.salt = os.urandom(16)          # Generate 16 random bytes
        self.salted_pwd = pbkdf2_hmac('sha256', pwd.encode('utf-8'), self.salt, self.c, self.dkLen)
    
    def get_saltedpwd(self):
        return self.salted_pwd
    
    def get_salt(self):
        return self.salt
    
    def verify_pwd(self, pwd):
        new_salted_pwd = pbkdf2_hmac('sha256', pwd.encode('utf-8'), self.salt, self.c, self.dkLen)
        return new_salted_pwd == self.salted_pwd


if __name__ == '__main__':    
    pwd = input("Enter your password: ")
    salted_pwd = SaltedPassword(pwd)
    print("Salted password: ", salted_pwd.get_saltedpwd())

    # Verify password
    new_pwd = input("Enter your password to verify: ")
    is_correct = salted_pwd.verify_pwd(new_pwd)
    print("Password Verification: ", is_correct)
