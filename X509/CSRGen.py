'''
X.509 certificates are used to authenticate clients and servers. The most common use case is for web servers using HTTPS.

Before getting a certificate, a client and/or server must generate a CSR (Certificate Signing Request), send it to a CA to request for a certificate.

CA will issue a certificate consisting the client/server's public key and other info. Sign on that and return to to client/server
'''
import os 
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_keys():
    # Generate a key pair first
    private_key = Ed448PrivateKey.generate()        # Get 57 byte key value
    public_key = private_key.public_key()
    return private_key, public_key

def export_private_key(private_key, file_name):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"MyPassword"))


    with open(file=file_name, mode="wb") as f: 
        f.write(pem_private_key)

def load_private_key(file_name):
    with open(file=file_name, mode="rb") as f:
        pem_private_key = f.read()

    return serialization.load_pem_private_key(pem_private_key, password=b"MyPassword")

def generate_crs(private_key):
    crs = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ontario"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ottawa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My porfolio"),
        x509.NameAttribute(NameOID.COMMON_NAME, "dple.github.io"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
        x509.DNSName("dple.github.io"),
        x509.DNSName("www.dple.github.io"),
        ]), 
        critical=False,
    ).sign(private_key, None)

    return crs

if __name__ == '__main__':
    privkey, pubkey = generate_keys()
    fname = "X509/privkey.pem"
    export_private_key(privkey, fname)

    loaded_privkey = load_private_key(fname)

    cert = generate_crs(loaded_privkey).public_bytes(
        encoding=serialization.Encoding.PEM
    )
    
    with open("X509/cert.pem", "wb") as f:
        f.write(cert)

    