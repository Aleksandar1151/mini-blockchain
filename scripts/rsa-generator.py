import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Create a directory named "keys" if it doesn't exist
keys_folder = "keys"
if not os.path.exists(keys_folder):
    os.makedirs(keys_folder)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize and save private key
private_key_path = os.path.join(keys_folder, "node2_private_key.pem")
with open(private_key_path, "wb") as f:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(pem)

# Serialize and save public key
public_key_path = os.path.join(keys_folder, "node2_public_key.pem")
with open(public_key_path, "wb") as f:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(pem)

print("RSA keys generated and saved successfully.")

