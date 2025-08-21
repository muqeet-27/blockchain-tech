from ecdsa import SigningKey, SECP256k1, VerifyingKey
import hashlib
import os
import binascii

def generate_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    return sk.to_string().hex(), vk.to_string().hex()

def create_zk_proof(priv_key_hex, challenge):
    # ZKP Circuit 1: Schnorr proof of knowledge
    sk = SigningKey.from_string(bytes.fromhex(priv_key_hex), curve=SECP256k1)
    random_bytes = os.urandom(32)
    random_int = int.from_bytes(random_bytes, 'big') % SECP256k1.order
    g = SECP256k1.generator
    commitment_point = random_int * g
    commitment = binascii.hexlify(commitment_point.to_bytes()).decode()
    
    hash_challenge = int(hashlib.sha256(challenge.encode()).hexdigest(), 16) % SECP256k1.order
    response = (random_int + hash_challenge * sk.privkey.secret_multiplier) % SECP256k1.order
    return commitment, str(response)

def verify_zk_proof(pub_key_hex, challenge, commitment, response):
    # Verification for Circuit 1
    vk = VerifyingKey.from_string(bytes.fromhex(pub_key_hex), curve=SECP256k1)
    pub_point = vk.pubkey.point
    g = SECP256k1.generator
    
    response_point = int(response) * g
    hash_challenge = int(hashlib.sha256(challenge.encode()).hexdigest(), 16) % SECP256k1.order
    challenge_pub = hash_challenge * pub_point
    expected_commitment = response_point - challenge_pub
    
    expected_commitment_bytes = expected_commitment.to_bytes()
    return binascii.hexlify(expected_commitment_bytes).decode() == commitment

# Note: Second circuit (attribute proof) can be added similarly, e.g., proving hash(value) matches without revealing value.