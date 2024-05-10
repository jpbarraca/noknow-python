from getpass import getpass
import requests
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
import uuid


print("Registering client")
client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
clientid = uuid.uuid4().hex
password = getpass("Enter Password: ")
# Create signature and send to server
signature = client_zk.create_signature(password)
print("Client: signature ", signature.to_json())
r = requests.post("http://localhost:5000/register", json={"clientid": clientid, "sig": signature.to_json()})
print(r.status_code)

input("Press Enter to continue...")

print("Logging in")
password = getpass("Enter Password: ")
print("Getting token...")
r = requests.post("http://localhost:5000/login", json={"clientid": clientid})
print("Token: ", r.json())
token = r.text
proof = client_zk.sign(password, token).to_json()

print("Proof: ", proof)
print("Sending proof...")

r = requests.post("http://localhost:5000/login", json={"clientid": clientid, "proof": proof})
print(r.text)
