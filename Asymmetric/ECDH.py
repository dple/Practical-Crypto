from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH

privA = generate_private_key(SECP256R1())
privB = generate_private_key(SECP256R1())

pubA = privA.public_key()
pubB = privB.public_key()

RsharedA = privA.exchange(ECDH(), pubB)
RsharedB = privB.exchange(ECDH(), pubA)


assert RsharedA == RsharedB