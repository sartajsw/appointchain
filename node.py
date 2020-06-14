# Import libraries
import json
import hashlib
import binascii

import requests
from datetime import datetime
from urllib.parse import  urlparse

# Cryptography libraries
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


# Build the Wallet
class Wallet(object):
    """
    A wallet is a private/public key pair
    Using RSA digital signature protocol
    """
    def __init__(self):
        random_gen = Crypto.Random.new().read
        self.private_key = RSA.generate(1024, random_gen)
        self.public_key = self.private_key.publickey()
        self.signer = PKCS1_v1_5.new(self.private_key)


    @property
    def address(self):
        """
        Assume public key is address
        """
        # Get address from public key
        address = self.public_key.exportKey(format='DER')
        
        return binascii.hexlify(address).decode('ascii')
    
    
    def sign(self, message):
        """
        Sign a message with this wallet
        """
        message = message if type(message) == str else str(message)
        # Hash message
        h = SHA.new(message.encode('utf8'))
        # Sign encoded message
        signature = self.signer.sign(h)
        
        return binascii.hexlify(signature).decode('ascii')
    
    
    def create_transaction(self, host_address, time_slot, amount):
        """
        Create a transaction with the wallet
        """
        # Get public key
        public_key = self.public_key.exportKey(format='DER')
        # Use public key as address
        sender_address = binascii.hexlify(public_key).decode('ascii')
        # Build transaction
        trans_dict = {'sender_address': sender_address,
                      'host_address': host_address,
                      'time_slot': time_slot,
                      'amount': amount}
    
        signature = self.sign(trans_dict)
        
        return {'message': trans_dict, 'signature': signature}
    
    
    def show_appointments(self, blockchain):
        # Get completed transactions
        completed_trans = []
        for block in blockchain.chain:
            for temp in block['transactions']:
                completed_trans.extend(temp['message'])
        
        
        # Get public key
        public_key = self.public_key.exportKey(format='DER')
        # Use public key as address
        address = binascii.hexlify(public_key).decode('ascii')
        
        # Get the appointments
        appointments = []
        for completed_tran in completed_trans:
            if completed_tran['sender_address'] == address:

                # Get booked time slot
                booked_slot = completed_tran['time_slot']
                booked_slot = [time.strip() for time in booked_slot.split('-')]
                
                appointments.append(booked_slot)
                
        return appointments
    
    
# Build the blockchain
class Blockchain:
    def __init__(self):
        self.chain = [] # Holds all blocks in the chain
        self.transactions = [] # To store transactions before adding to blockchain
        self.create_block(proof = 1, previous_hash = '0') # Create genesis block
        self.nodes = {} # Hold addresses of nodes
        # Address : [Location, Fee]
        # Blocked requesters


    def create_block(self, proof, previous_hash):
        # Create a block and add it to the block chain
        block = {'index': len(self.chain)+1,
                 'timestamp': str(datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
		         'transactions': self.transactions}
        self.transactions = [] # Empty transactions
        self.chain.append(block) # Append the block to the chain
        return block


    def get_previous_block(self):
        # Get the previous block
        return self.chain[-1]


    def proof_of_work(self, previous_proof):
        # To find new proof of work (AKA nonce)
        # Define new proof
        new_proof = 1
        check_proof = False
        
        # Loop till prrof is found
        while check_proof is False:
            # Use a non  commutative equation with new and previous proof
            # Find the hash of equation
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            
            # Verify is suitable hash found
            # Increase required number of 0's to increase difficulty
            if hash_operation[:4] == '0000':
                # Found proof, break loop
                check_proof = True
            else:
                # Increment & try again
                new_proof += 1
        
        # Return new proof
        return new_proof


    def hash(self, block):
        # Convert the dict to json
        # Encode to UTF-8
        encoded_block = json.dumps(block, sort_keys = True).encode()
        
        # Hash the encoded block
        # Returns the encoded data in hexadecimal format
        return hashlib.sha256(encoded_block).hexdigest()


    def is_chain_valid(self, chain):
        # Check if chain is valid
        # Define previous block and index
        previous_block = chain[0]
        block_index = 1

        # Loop through the blockchain
        while block_index < len(chain):
            # Get block
            block = chain[block_index]

            # Verify previous hash and block
            if block['previous_hash'] != self.hash(previous_block):
                return False
			
            # Verify previous proof and proof
            previous_proof = previous_block['proof']
            new_proof = block['proof']
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
			
            if hash_operation[:4] != '0000':
                return False

            # Increment and continue
            previous_block = block
            block_index += 1

        # No errors found, return valid
        return True


    def validate_transaction(self, transaction):
        # Get current transaction
        trans = transaction['message']
        address = trans['sender_address']

        # Verify signature
        if self.verify_signature(address, transaction):
            
            # Get completed transactions
            completed_trans = []
            for block in self.chain:
                for temp in block['transactions']:
                    completed_trans.append(temp['message'])
            
            # Get time slot
            if trans['amount'] > 0:
                form = '%d/%m/%y %H:%M:%S'
                time_slot = trans['time_slot']
                start, end = [datetime.strptime(time.strip(), form) 
                              for time in time_slot.split('-')]
    
            
            # Get amount
            amount = trans['amount']
            
            balance = 0
            for completed_tran in completed_trans:
                if completed_tran['host_address'] == trans['host_address']:
                    # Add amount to balance
                    balance += completed_tran['amount']
                    
                    # Get booked time slot
                    if trans['amount'] > 0:
                        booked_slot = completed_tran['time_slot']
                        booked_slot = [datetime.strptime(time.strip(), form) 
                                       for time in booked_slot.split('-')]
                        
                        # Overlapping slot
                        if all([start <= x <= end for x in booked_slot]):
                            # Invalid Transaction
                            return False
            
            # Insufficient balance
            if balance < amount:
                # Invalid Transaction
                return False
            
            # No issue
            return True
        
        # Invalid Signature
        return False
        
        
    def add_transaction(self, transaction):
        # Validate transaction 
        if self.validate_transaction(transaction):
            
            # Add the transaction
            self.transactions.append(transaction)
            
            # Get previous block
            previous_block = self.get_previous_block()
            # Return index of new block
            return previous_block['index'] + 1
        
        # Invalid Transaction
        return None


    def verify_signature(self, wallet_address, transaction):
        """
        Check that the provided `signature` corresponds to `message`
        signed by the wallet at `wallet_address`
        """
        # Get message and signature from transaction
        message = str(transaction['message'])
        signature = transaction['signature']
        
        # Import public key from address
        pubkey = RSA.importKey(binascii.unhexlify(wallet_address))
        
        # Verify message
        verifier = PKCS1_v1_5.new(pubkey)
        h = SHA.new(message.encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def add_node(self, node):
        # Add node to the network
        address = node['address']
        location = node['location']
        fee = node['fee']
        
        # Parse the node address
        parsed_url = urlparse((address)).netloc
       
        # Add to nodes list
        if parsed_url not in self.nodes.keys():
            # Address not in nodes yet
            self.nodes[parsed_url] = {'location': location,
                                      'fee': fee}


    def replace_chain(self):
        # Consensus of our network
        # Check if you have the longest chain and replace chain if not
        # Get all nodes
        network = self.nodes
        longest_chain = None
        
        # Init max length as current length
        max_length = len(self.chain)
        
        # Loop all nodes in the network
        for node in network:
            # Get http response
            response = requests.get(f'http://{node}/get_chain')
            
            # If request is successful
            if response.status_code == 200:
                # Get chain and chain length
                length = response.json()['length']
                chain = response.json()['chain']
                
                # Check lengths
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        
        # Replace current chain with ongest chain
        if longest_chain:
            self.chain = longest_chain
            return True
        
        # Not replaced
        return False


# Mining the blockchain

# Create a Wallet
wallet = Wallet()

## Create Blockchain instance
blockchain = Blockchain()


def mine_block(blockchain, wallet):
    # Get previous block and proof
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']

    # Calculate proof of work
    proof = blockchain.proof_of_work(previous_proof)
    
    # Calculate previous hash
    previous_hash = blockchain.hash(previous_block)
    
    # Add the mining reward
    temp = wallet.create_transaction(wallet.address, "00:00", -1)
    
    # Add transaction to the blockchain
    blockchain.add_transaction(temp)
    
    # Add the block to the blockchain
    block = blockchain.create_block(proof, previous_hash)

    # Create response to send
    response = {'Message': 'Congrats! You just mined a block.',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']}

    return response


def get_chain(blockchain):
    # Get chain
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}

    return response


def chain_valid(blockchain):
    # Verify the blockchain
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    
    # Create response
    if is_valid:
        response = {'Message': 'Yes'}
    else:
        response = {'Message': 'No'}
        
    return response


def add_transaction(data):
    # Transaction keys
    transaction_keys = ['transaction']
        
    # Check if transaction has all keys
    if not all (key in data for key in transaction_keys):
    	# Return response code
        return "Missing key", 400
    
    # Add transaction to the blockchain
    index = blockchain.add_transaction(data['transaction'])

    # Create a response
    response = {'Message': 'This transactions will be added', 'Index': index}
    return response


def connect_nodes(blockchain, data):
    # Nodes currently in the network
    nodes = data.get("nodes")

    # If there are no nodes in the network
    if nodes is None:
        return "No nodes", 400

    # Loop over all nodes in the network
    for node in nodes:
        # Send new node address to all nodes
        blockchain.add_node(node)

    # Create response
    response = {'Message': 'All nodes connected. The nodes are: ',
                'total_nodes': list(blockchain.nodes)}

    return response


def replace_chain(blockchain):
    # Replace the chain
    is_chain_replaced = blockchain.replace_chain()
    
    # If chain has been replaced
    # Create response
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return response


def show_trans(blockchain):
    # Show all transactions
    response = {'message': 'Showing all unconfirmed transactions',
                'transactions': blockchain.transactions}
    
    return response


def show_hosts(blockchain):
    # Get nodes
    nodes = blockchain.nodes
    locations = [node[0] for node in nodes]
    
    # Create a response
    response = {'Message': 'Showing all host locations',
                'Locations': locations}
    return response

# TODO: Add flask again
