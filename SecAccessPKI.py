#importing required libraries and modules
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature
import hashlib

# The message
text = 'Hello world!'

# creates a hash value of the message
m = hashlib.sha512(text.encode('UTF-8'))
print("The hash value of the message is:")

# prints the hash value (hexadecimal encoded hash value) of the message
print(m.hexdigest())
digest_hex = m.hexdigest()

# Generate the bytes format of the message(digest) to sign
message = bytes.fromhex(digest_hex)

# Generating the RSA key pair ( private and public keys)

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

# Sign the message with the private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

#Printing the digital signature in hex format
print("Digital Signature:")
signature_hex = signature.hex()
print(signature_hex)

# Verify the signature using the public key
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    print("Signature is valid.")
except InvalidSignature:
    print("Signature is not valid.")