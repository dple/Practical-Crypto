"""
Ed25519 is a alternative of ECDSA-256 for digital signature.
The algorithm uses the hash function SHA-512 and the twisted elliptic curve Ed25519, where
    - q: order of finite field Fq, = 2^255 - 19
    - E/Fp: a twisted elliptic curve, birationally equivalent to Curve25519 (Montgomery form):
            -x^2 + y^2 = 1 - 121665/121666 x^2 y^2


Note: In Python, cryptography package supports Ed25519 and Ed448 as EdDSA. 
      They works exactly the same, but just different curves, and hence different security level

                            Ed25519                 Ed448
        Private key         32-bytes                57 bytes
        Signature           64 bytes                114 bytes        
        Hash                SHA-512                 SHAKE256
        Security            128 bit                 224 bit
        Performance         faster                  slower
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_keys():
    ''' Key generation '''
    private_key = Ed25519PrivateKey.generate()          # Return a 32-bytes private key
    public_key = private_key.public_key()               # Get public key from the private key pk = d*G, where G is Ed25519 generator
    
    return private_key, public_key

def export_private_key(private_key):
    ''' There are several common schemes for serializing asymmetric private and public keys to BYTES.
        - PEM: a text-based, Base64 encoding, and human-readable for X.509 certificates, CSRs, and cryptographic keys. . File extension: crt, pem, cer, key
                Begin with -----BEGIN {format}----- and end with -----END {format}-----. 
        - DER: an ASN.1 encoding type, binary encoding for X.509 certificates and private keys, less human-readable. File extension: der, cer  
        - OpenSSH: format for certiciates and public/private keys. File extension: pk, pubk 
        - PKCS#7: a container format for digital certificates (NOT for private key) that is most often found in Windows and Java server contexts. File extension: P7B
        - PKCS#12:  a common binary format for storing a certificate chain and private key in a single, encryptable file. File extension: p12, pfx

    Note that: these format can be converted from one to another. E.g., using openssl:
            openssl x509 -outform der -in CERTIFICATE.pem -out CERTIFICATE.der

    '''
    private_pem = private_key.private_bytes(            
        encoding=serialization.Encoding.PEM,                # Export private key as PEM. Other options: DER, Raw, ...         
        format=serialization.PrivateFormat.PKCS8,           # PKCS#8: a standard syntax for storing private key information. Other option: Raw
        encryption_algorithm=serialization.NoEncryption()   # Don't encrypt the private key, but do in production 
    )

    return private_pem

def export_public_key(public_key):    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,                        # Export public key as PEM
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem
    
def load_private_key(private_pem):
    ''' Load private key from PEM '''
    return serialization.load_pem_private_key(private_pem, password=None)

def load_public_key(public_pem):
    ''' Load public key from PEM '''
    return serialization.load_pem_public_key(public_pem)

def signature_generation(message, private_key):
    ''' Sign a (encoded) message, a bytes-object, using private key 
        Message will be hashed using SHA-512 before signing
        Output: 64 bytes, two elements (R, S), where R: EC point, and S is integer (mod #E/Fq, order of EC)
    '''
    return private_key.sign(message)

def signature_verification(sig, message, public_key):
    ''' Verify a signature of a (encoded) message using public key '''
    try:
        public_key.verify(sig, message)
        return True
    except:
        return False

if __name__ == '__main__':

    private_key, public_key = generate_keys()
    
    # Serialize keys (Optional: for storing keys)
    private_pem = export_private_key(private_key)
    print("Serializing private key: ", private_pem)


    public_pem = export_public_key(public_key)
    print("Serializing public key: ", public_pem)
    

    # Generate a signature using private key
    message = "This is a EdDSA using Curve25519!"    
    # Convert a string into a bytes-object 
    message_encoded = bytes(message, 'utf-8') #or simply use encode() method: message.encode()
    print(message_encoded)
    sig = signature_generation(message_encoded, private_key)


    print("Signature (hex): ", sig.hex())

    # Verify the signature 
    if signature_verification(sig, message_encoded, public_key):
        print("Signature is valid!")
    else:
        print("Signature is invalid!")


    loaded_public_key = load_public_key(public_pem)
    if signature_verification(sig, message_encoded, loaded_public_key):
        print("Signature is valid with loaded key!")
    else:
        print("Signature is invalid with loaded key!")