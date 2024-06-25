from ecdsa import SigningKey, VerifyingKey, NIST384p
import hashlib

# Generate a new private key (signing key) using the NIST384p curve
private_key = SigningKey.generate(curve=NIST384p)

# Get the corresponding public key (verifying key)
public_key = private_key.get_verifying_key()

# Message to be signed
message = "This is a secret message."
message_bytes = message.encode('utf-8')

# Sign the message using the private key
signature = private_key.sign(message_bytes, hashfunc=hashlib.sha256)

print("Message:", message)
print("Signature:", signature.hex())

# Verify the signature using the public key
try:
    public_key.verify(signature, message_bytes, hashfunc=hashlib.sha256)
    print("The signature is valid.")
except:
    print("The signature is invalid.")

# Demonstrate verification failure with a modified message
modified_message = "This is a modified message."
modified_message_bytes = modified_message.encode('utf-8')

try:
    public_key.verify(signature, modified_message_bytes, hashfunc=hashlib.sha256)
    print("The signature is valid for the modified message.")
except:
    print("The signature is invalid for the modified message.")
