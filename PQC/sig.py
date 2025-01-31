# signature Python example

from pprint import pprint
import oqs

#######################################################################
# signature example
#######################################################################

sigs = oqs.get_enabled_sig_mechanisms()

print("Enabled signature mechanisms:")
pprint(sigs, compact="True")

message = "This is the message to sign".encode()

sigalg = "Dilithium5"

sig = oqs.Signature(sigalg)
print("\nSignature details:")
pprint(sig.details)

# Generate key pair
public_key = sig.generate_keypair()
print(sigalg, "'s Public key:\n", public_key.hex())

signature = sig.sign(message=message)
print("\nSignature:\n", signature.hex())

# Verify the signature
is_valid = sig.verify(message, signature, public_key)

print("\nValid signature?", is_valid)
