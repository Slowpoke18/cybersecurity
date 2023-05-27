from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib

text = 'Hello!'

m = hashlib.sha512(text.encode('UTF-8'))
print(m.hexdigest())

# Generate random private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

digest_hex = m.hexdigest()

# Get the public key from the private key
public_key = private_key.public_key()

# Generate a message to sign
message = bytes.fromhex(digest_hex)

# Sign the message with the private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

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