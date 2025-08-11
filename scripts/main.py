import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# project root = parent of this file's folder
PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEYS_DIR = PROJECT_ROOT / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"


# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    #backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open(PRIVATE_KEY_PATH, "wb") as private_key_file:
    private_key_file.write(private_key_pem)

# Get the message from the user
message = "Secret message."

# Hash the message using SHA256
hasher = hashlib.sha256()
hasher.update(message.encode())
digest = hasher.digest()

# Encrypt the digest using the public key
ciphertext = public_key.encrypt(
    digest,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open(PRIVATE_KEY_PATH, "rb") as private_key_file:
    private_key_pem_read = private_key_file.read()

# Deserialize the private key from PEM format
private_key = serialization.load_pem_private_key(
    private_key_pem_read,
    password=None,
    backend=default_backend()
)

# Decrypt the ciphertext using the private key
decrypted_digest = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Verify the integrity of the decrypted digest
hasher = hashlib.sha256()
hasher.update(message.encode())
expected_digest = hasher.digest()

if decrypted_digest == expected_digest:
    print("Decryption successful.")
else:
    print("Decryption failed.")
