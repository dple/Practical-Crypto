# key encapsulation Python example

from pprint import pprint
import oqs

#######################################################################
# KEM example
#######################################################################


print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("Enabled KEM mechanisms:")
kems = oqs.get_enabled_kem_mechanisms()
pprint(kems, compact=True)

# Create client and server with sample KEM mechanisms
kemalg = "ML-KEM-1024"
with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        print("\nKey encapsulation details:")
        pprint(client.details)

        # Generate key pair
        public_key_client = client.generate_keypair()
        print("Public Key:", public_key_client.hex())

        # Server encapsulate (encrypt) a shared secret using the client's public key
        ciphertext, shared_secret_enc = server.encap_secret(public_key_client)
        print("Ciphertext:", ciphertext.hex())
        print("Encapsulated Shared Secret:", shared_secret_enc.hex())

        # Client decapsulate (decrypt) to get the shared secret
        shared_secret_dec = client.decap_secret(ciphertext)
        print("Decapsulated Shared Secret:", shared_secret_dec.hex())

        # Verify both parties have the same secret
        assert shared_secret_enc == shared_secret_dec
        print("Key exchange successful!")
        client.free()
        server.free()