from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# Key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,                  # e = 2^16 + 1 for fast encryption 
    key_size=2048,                          # size of the modulus N
)

public_key = private_key.public_key()

# Serialize keys (Optional: for storing keys)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,                    # PEM, base64 format, starts with -----BEGIN {format}-----, and end with -----END {format}-----
                                                            # Other encoding:   1) DER (ASN.1 encoding type), a binary format. 
                                                            #                   2) OpenSSH for OpenSSH public key, a text format

    format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS#1, a preferred format for storing private key is PKCS#8
                                                            # format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()       # if wanted, you can encrypt the private key using a password
                                                            # serialization.BestAvailableEncryption(password)
)

print("Serializing private key: ", private_pem, "\n")

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Serializing public key: ", public_pem, "\n")

# Encryption
message = b"Secret message"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),        # pad the plaintext using OAEP
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decryption
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Sign the message 
sig = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), 
        salt_length=padding.PSS.MAX_LENGTH),
    algorithm=hashes.SHA256()
)

# Verify the signature
public_key.verify(
    sig, 
    message, 
    padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), 
        salt_length=padding.PSS.MAX_LENGTH),
    algorithm=hashes.SHA256()
)


print("Original message:", message, "\n")
print("Decrypted message:", plaintext)

print("Signature is:", sig) #.decode())
print("Signature verified successfully!")