from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_keys():
    ''' Key generation '''
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    return private_key, public_key

def export_private_key(private_key):
    ''' Export private key as PEM '''
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return private_pem

def export_public_key(public_key):
    ''' Export public key as PEM '''
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
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
    ''' Sign a (encoded) message using private key '''
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
    message_encoded = message.encode()
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