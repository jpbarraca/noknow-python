from flask import Flask
from flask import request
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
import os
import json

app = Flask(__name__)

clients = {}

@app.route("/")
def index():
    return "Howdy"

@app.route("/register", methods=["POST"])
def register():
    clientid = request.json.get('clientid', None)
    sig = request.json.get('sig', None)
    
    if sig is None or clientid is None:
        return "Invalid request"
    
    if clientid in clients:
        return "Client already registered"

    client_signature = ZKSignature.from_json(sig)
    client_zk = ZK(client_signature.params)
    clients[clientid] = {'zk': client_zk, 'sig': client_signature}

    return "Client registered"


@app.route("/login", methods=["POST"])
def login():
    clientid = request.json.get('clientid', None)
    proof = request.json.get('proof', None)


    # First request, send token to client for proof
    if clientid in clients and proof is None:
        
        # Generate a server password and ZK object for the server
        server_password = os.urandom(32)
        # Set up server component, generating a new ZK object
        server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        # store the server zk and password for later use
        clients[clientid]['server_zk'] = server_zk
        clients[clientid]['server_password'] = server_password
        # get the client zk 
        client_zk = clients[clientid]['zk']

        # Create a signed token and send to the client
        token = server_zk.sign(server_password, client_zk.token())
        return token.to_json()

    if clientid in clients and proof is not None:
        # Get the token from the client
        zkproof = ZKData.from_json(proof)
        token = ZKData.from_json(zkproof.data)

        # Get the client zk and server password
        server_zk = clients[clientid]['server_zk']
        server_signature = server_zk.create_signature(clients[clientid]['server_password'])
        client_zk = clients[clientid]['zk']

        # check if the server signature is valid
        if not server_zk.verify(token, server_signature):
            print("Invalid server auth: ")
            return "Authentication failure"
        else:
            # Verify the proof from the client
            # uses the client proof and signature to verify the token
            result = client_zk.verify(zkproof, clients[clientid]['sig'], data=token)
            return "Authentication success" if result else "Authentication failure"
    
    # Invalid request
    return "Invalid request"

if __name__ == "__main__":
    app.run(debug=True)
