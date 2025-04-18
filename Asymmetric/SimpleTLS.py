from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# Generate Server's RSA key pair 
server_privkey = rsa.generate_private_key(public_exponent=2**16 + 1, key_size=2048)

# Serialize keys (Optional: for storing keys)
server_priv_pem = server_privkey.private_bytes(
    encoding=serialization.Encoding.PEM,                    # PEM, base64 format, starts with -----BEGIN {format}-----, and end with -----END {format}-----
                                                            # Other encoding:   1) DER (ASN.1 encoding type), a binary format. 
                                                            #                   2) OpenSSH for OpenSSH public key, a text format

    format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS#1, a preferred format for storing private key is PKCS#8
                                                            # format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()       # if wanted, you can encrypt the private key using a password
                                                            # serialization.BestAvailableEncryption(password)
)

print("Serializing private key: ", server_priv_pem, "\n")

server_pubkey = server_privkey.public_key()

server_pub_pem = server_pubkey.public_bytes(
    encoding=serialization.Encoding.PEM, 
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Serializing public key: ", server_pub_pem, "\n")

# Client generates a random as a session key
session_key = os.urandom(32)        # 32 bytes = 256 bits (e.g., for AES256)

# Client encrypt the session key by using server public key
encrypted_session_key = server_pubkey.encrypt(
    session_key, 
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Server decrypts the encrypted session key to get the session key
decrypted_session_key = server_privkey.decrypt(
    encrypted_session_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

assert session_key == decrypted_session_key
print("Session key:", str(session_key))