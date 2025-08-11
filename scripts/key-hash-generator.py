import hashlib

# Specify the path to the public key file
public_key_file = 'keys/node2_public_key.pem'
output_file = 'keys/node2_public_hash.txt'
# Load the public key from file
with open(public_key_file, 'rb') as file:
    public_key = file.read()

# Apply hash function to the public key
hashed_key = hashlib.sha256(public_key).hexdigest()

# Write the hashed key to the output file
with open(output_file, 'w') as file:
    file.write(hashed_key)
