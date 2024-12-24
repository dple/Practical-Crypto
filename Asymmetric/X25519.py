"""
DH Key exchange using Curve 25519
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os

def generate_keys():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)
       

if __name__ == '__main__':
    private_key_A, public_key_A = generate_keys()
    private_key_B, public_key_B = generate_keys()

    # Serialize keys (Optional: for storing keys)
    private_pem_A = private_key_A.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem_A = public_key_A.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Serializing private key (Alice): ", private_pem_A)  
    print("Serializing public key: ", public_pem_A)

    private_pem_B = private_key_A.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem_B = public_key_A.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Serializing private key (Bob): ", private_pem_B)  
    print("Serializing public key (Bob): ", public_pem_B)

    # Derived shared key 
    shared_key_A = derive_shared_key(private_key_A, public_key_B)
    shared_key_B = derive_shared_key(private_key_B, public_key_A)

    assert shared_key_A == shared_key_B, "Shared secrets do not match!"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), info=b'DH Key Exchange')
    derived_key = hkdf.derive(shared_key_A)

    print("Shared secret:\n", derived_key.hex())  