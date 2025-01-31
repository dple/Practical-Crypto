from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os 

def argon2(passwd, salt, length, iterations, lanes, memory_cost):
    kdf = Argon2id(salt=salt, length=length, iterations=iterations, lanes=lanes, memory_cost=memory_cost, ad=None, secret=None)    
    return kdf.derive(passwd)

def pbkdf2(passwd, length, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iter, backend=None)
    return kdf.derive(passwd)

def scrypt(passwd, salt, length, paral):
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=paral)
    return kdf.derive(passwd)

if __name__ == '__main__':
    pwd = b'my_secure_password'
    salt = os.urandom(16)
    len = 32        # bytes
    iter = 10       # iterations
    parallelism = 4
    memory_cost = 64*1024   # 64 MB
    print("Key derived from Argon2", argon2(pwd, salt, len, iter, parallelism, memory_cost).hex())
    print("Key derived from PKKDF2", pbkdf2(pwd, len, salt, iter).hex())
    print("Key derived from Scrypt", scrypt(pwd, salt, len, parallelism).hex())

    

    
