import hashlib 

#Define a hashing algorithm
HASH_FUNCTION = lambda inupt: hashlib.sha256(input)
#Define a proof of work function
BLOCKCHAIN_PROBLEM_OPERATION_LAMBDA = lambda previous_proof, new_proof : new_proof**2 - previous_proof**2
#Define the number of leading zeros
LEADING_ZEROS = '0000'

#Web App Configuration
HOST = '127.0.0.1'
PORT = '5002'