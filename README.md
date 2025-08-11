\# MiniBlockchain

MiniBlockchain is a simple decentralized blockchain network built in Python using Flask.

The project simulates multiple nodes communicating with each other through a REST API. Each node maintains its own blockchain, can add transactions, mine new blocks, and synchronize with other nodes in the network.


\## Technologies

The application is written in Python and uses several key libraries:

\- Flask for building the API

\- Requests for HTTP communication between nodes

\- Hashlib for SHA256 hashing

\- Cryptography (in extended versions) for digital signatures



\## Project structure

The project contains scripts for running three independent nodes:

\- corgicoin\_node\_5001.py

\- corgicoin\_node\_5002.py

\- corgicoin\_node\_5003.py

There is also a config.py file with global settings, and optionally a Keys folder used for storing keys if you are running the version with transaction signing.



\## Installation

First, clone the repository:

```

git clone https://github.com/your-username/corgicoin.git

cd corgicoin

```

It is recommended to create a virtual environment:

```

python3 -m venv venv

source venv/bin/activate   # on Linux/Mac

venv\\Scripts\\activate      # on Windows

```

Then install the dependencies:

```
python.exe -m pip install --upgrade pip --user
python -m pip install --upgrade pip setuptools wheel

pip install -r requirements.txt

```



\## Configuration

In config.py you can set the host IP address, the port, and the mining difficulty (the number of leading zeros).

If you are using the version with digital signatures, you need to generate RSA keys and store them in the Keys folder.



\## Running the nodes

Each node needs to be started in a separate terminal. For example:</br>



Terminal 1:

```

python3 corgicoin\_node\_5001.py

```

Terminal 2:

```

python3 corgicoin\_node\_5002.py

```

Terminal 3:

```

python3 corgicoin\_node\_5003.py

```

## Get chain

```
curl -X POST http://127.0.0.1:5001/connect-node
```

\## Connecting nodes

Once the nodes are running, you can connect them by sending a POST request. For example, to connect the node running on port 5001 to the other two:

```

curl -X POST http://127.0.0.1:5001/connect-node \\

&nbsp;    -H "Content-Type: application/json" \\

&nbsp;    -d '{"nodes": \["http://127.0.0.1:5002", "http://127.0.0.1:5003"]}'

```

\## API routes

The application provides several main routes:

\- /mine-block – mines a new block and adds it to the chain

\- /get-chain – returns the full blockchain

\- /is-valid – checks if the blockchain is valid

\- /add-transaction – adds a new transaction

\- /connect-node – connects the current node to other nodes

\- /replace-chain – replaces the chain with the longest one in the network



\## Example usage

If you want to mine a block on the node running on port 5002:

```

curl http://127.0.0.1:5002/mine-block

```

Then on the node running on port 5001, you can fetch and replace the chain with:

```

curl http://127.0.0.1:5001/replace-chain

```



\## Possible issues

If you get an error saying Flask is not found, install it with pip install flask.

If a port is already in use, either change the port in the code or stop the process that is using it.

If the Keys folder is missing required key files, generate them before running the nodes.

