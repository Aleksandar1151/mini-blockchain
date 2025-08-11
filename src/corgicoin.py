import datetime
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import config
import requests
from uuid import uuid4
from urllib.parse import urlparse
# import flask_web_app
from flask import Flask, jsonify, request
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

port = None


class Blockchain:
    def __init__(self):
        # Initialize a chain which will contain blocks
        self.chain = []  # a simple list containing blovks
        # Create a list which contains a list of transactions before they
        # are added to the block. Think of it as a cache of transactions which
        # happened, but are not yet written to a block in a blockchain.
        self.transactions = []
        # Create a genesis block - the first block
        # Previous hash is 0 because this is a genesis block!
        self.create_block(proof=1, previous_hash='0')
        # Create a set of nodes
        self.nodes = set()

    def create_block(self, proof, previous_hash):
        # Define block as a dictionary
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 # Here we can add any additional data related to the currency
                 'transactions': self.transactions
                 }
        # Now we need to empty the transactions list, since all those transactions
        # are now contained in the block.
        self.transactions = []
        # Append block to the blockchain
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1  # nonce value
        check_proof = False
        while check_proof is False:
            # Problem to be solved (this makes the minig hard)
            # operation has to be non-symetrical!!!
            hash_operation = hashlib.sha256(
                str(config.BLOCKCHAIN_PROBLEM_OPERATION_LAMBDA(previous_proof, new_proof)).encode()).hexdigest()
            # Check if first 4 characters are zeros
            if hash_operation[:len(config.LEADING_ZEROS)] == config.LEADING_ZEROS:
                check_proof = True
            else:
                new_proof += 1
        # Check proof is now true
        return new_proof

    def hash_of_block(self, block):
        # Convert a dictionary to string (JSON)
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def verify_signature(self, signature, data):

        public_key_ser = None

        if port == '5000':
            with open("Keys/node2_public_key.pem", 'rb') as file:
                public_key_ser = file.read()
        elif port == '5001':
            with open("Keys/node1_public_key.pem", 'rb') as file:
                public_key_ser = file.read()

        # Deserialize the public key
        public_key = serialization.load_pem_public_key(public_key_ser)

        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def are_transactions_valid(self):

        for transaction in self.transactions:
            sender = transaction['sender']
            receiver = transaction['receiver']
            amount = transaction['amount']
            signature = transaction['signature']

            # Create a hash of the transaction data (sender, receiver, amount)
            transaction_data = {
                'sender': sender,
                'receiver': receiver,
                'amount': amount
            }
            transaction_bytes = json.dumps(transaction_data).encode()
            transaction_hash = hashlib.sha256(transaction_bytes).hexdigest()



            # Compare the computed hash with the decrypted signature
            if not self.verify_signature(signature, transaction_hash):
                return False

        return True

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            # 1 Check the previous hash
            block = chain[block_index]
            if block['previous_hash'] != self.hash_of_block(previous_block):
                return False
            # 2 Check all proofs of work
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(config.BLOCKCHAIN_PROBLEM_OPERATION_LAMBDA(previous_proof, proof)).encode()).hexdigest()
            if hash_operation[:len(config.LEADING_ZEROS)] != config.LEADING_ZEROS:
                return False
            # 3 Check all transactions in blockchain
            if not self.are_transactions_valid():
               return False
            # Update variables
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, amount, signature):
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount,
                                  'signature': signature})
        # Return the index of the next block in a blockchain
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        # Add to the list of nodes
        # parsed_url() method returns ParseResult object which has an attribute netloc
        # which is in a format address:port eg. 127.0.0.1:5000
        self.nodes.add(parsed_url.netloc)
        # self.nodes.add(address)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            # Find the largest chain (send a request)
            response = requests.get(f'http://{node}/get-chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # Check chain if it is the longest one and also a valid one
                if length > max_length and chain.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            # Replace the chain
            self.chain = longest_chain
            return True
        # Otherwise, the chain is not replaced
        return False


def load_private_key():
    private_key = None

    if port == '5000':
        # Load the serialized private key from the "Keys" folder
        private_key_path = os.path.join("Keys", "node1_private_key.pem")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    elif port == '5001':
        # Load the serialized private key from the "Keys" folder
        private_key_path = os.path.join("Keys", "node2_private_key.pem")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    return private_key


# ======================= FLASK APP ===========================================


# Create a Web App (Flask-based)
app = Flask(__name__)

# Creating an address for node on Port 5000
#
node_address = None

if port == "5000":
    with open("Keys/node1_public_hash.txt", "r") as file:
        node_address = file.read().strip()
elif port == "5001":
    with open("Keys/node2_public_hash.txt", "r") as file:
        node_address = file.read().strip()

# Create a Blockchain
blockchain = Blockchain()


# Minig a block
@app.route('/mine-block', methods=['GET'])
def mine_block():
    global port
    port = request.environ.get('SERVER_PORT')
    # Get the previous proof
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    # Get previous hash
    previous_hash = blockchain.hash_of_block(previous_block)
    # Add new block to the blockchain
    block = blockchain.create_block(proof, previous_hash)
    # Add transactions (the receiver is the miner, an award for mining a block)

    transaction_data = {
        'sender': node_address,
        'receiver': 'Zelimir',
        'amount': 1
    }
    transaction_bytes = json.dumps(transaction_data).encode()

    # Load the private key
    private_key = load_private_key()
    print("private key:" + str(private_key))
    # Create a hash code of the transaction
    hash_algorithm = hashes.SHA256()
    hash_code = hashes.Hash(hash_algorithm)
    hash_code.update(transaction_bytes)
    digest = hash_code.finalize()

    # Encrypt the hash code with the private key
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_str = signature.hex()
    blockchain.add_transaction(sender=node_address, receiver='Zelimir', amount=1, signature=signature_str)
    # Generate a response as a dictionary
    response = {'message': 'Congratulations! You have just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']
                }

    print(response)
    # Create a JSON response and return it
    return jsonify(response), 200
    # return jsonify(response), 200


# Getting the full Blockchain
@app.route('/get-chain', methods=['GET'])
def get_chain():
    global port
    port = request.environ.get('SERVER_PORT')
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)
                }
    return jsonify(response), 200


# Checking if the blockchain is valid
@app.route('/is-valid', methods=['GET'])
def is_blockchain_valid():
    global port
    port = request.environ.get('SERVER_PORT')
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'The Blockchain is valid!'}
    else:
        response = {'message': 'The Blockchain is not valid!'}
    return jsonify(response), 200


# Adding a new transaction to the Blockchain
@app.route('/add-transaction', methods=['POST'])
def add_transaction():
    global port
    port = request.environ.get('SERVER_PORT')
    # Get the JSON file posted in Postman, or by calling this endpoint
    json = request.get_json()

    # Check all the keys in the received JSON
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'ERROR: Some elements of the transaction JSON are missing!', 400  # Bad Request code

    # Load the private key
    private_key = load_private_key()

    # Convert the JSON to bytes for hashing
    transaction_bytes = json.dumps(json).encode()

    # Create a hash code of the transaction
    hash_algorithm = hashes.SHA256()
    hash_code = hashes.Hash(hash_algorithm)
    hash_code.update(transaction_bytes)
    digest = hash_code.finalize()

    # Encrypt the hash code with the private key
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Add transaction to the next block,
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'], signature)
    response = {'message': f'This transaction will be added to block {index}'}
    return jsonify(response), 201  # Created code


# Decentralize a Blockchain

# Connecting new nodes
@app.route('/connect-node', methods=['POST'])
def connect_node():
    global port
    port = request.environ.get('SERVER_PORT')
    json = request.get_json()
    # Connect a new node
    nodes = json.get('nodes')  # List of addresses
    # Make sure that the list is not empty
    if nodes is None:
        return "ERROR: No node", 400
    # Loop over the nodes and add them one by one
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected.',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201  # Created code


# Replacing the chain by the longest chain if needed
@app.route('/replace-chain', methods=['GET'])
def replace_chain():
    global port
    port = request.environ.get('SERVER_PORT')
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The node had different chains, so the chain was replaced by the longest one!',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': ' All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200




# Running the app
if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT)
