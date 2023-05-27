from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import hashlib
text = 'Hello world!'

m = hashlib.sha512(text.encode('UTF-8'))
print(m.hexdigest())

digest_hex = m.hexdigest()


#jeevika
# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private key to PEM format
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print private key
print("Private Key:")
print(pem_private_key.decode())

# Print public key
print("Public Key:")
print(pem_public_key.decode())

# Generate a message to sign
message = bytes.fromhex(digest_hex)

# Sign the message with the private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify the signature using the public key
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid.")
except InvalidSignature:
    print("Signature is not valid.")
