'''
X.509 certificates are used to authenticate clients and servers. The most common use case is for web servers using HTTPS.

Before getting a certificate, a client and/or server must generate a CSR (Certificate Signing Request), send it to a CA to request for a certificate.

CA will issue a certificate consisting the client/server's public key and other info. Sign on that and return to to client/server
'''
import os 
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import serialization