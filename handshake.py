import argparse
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.exceptions import InvalidSignature

PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

GATEWAY_ROLE = b"gateway"
NODE_ROLE = b"node"

FIELD_WIDTH = 384
NONCE_SIZE = 16

def sha256(data):
    return hashlib.sha256(data).digest()

def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()
    
def int_to_fixed_bytes(value):
    """
    Encode a DH integer as exactly 384 bytes,
    big-endian, zero-padded on the left.
    """
    if value < 0:
        raise ValueError("Negative integer is invalid")
    try:
        return value.to_bytes(FIELD_WIDTH, "big")
    except OverflowError:
        raise ValueError("Integer does not fit in 384 bytes")

def encode_field(value):
    """
    Encode one transcript field as:
        4-byte big-endian length || field bytes
    """
    if not isinstance(value, bytes):
        raise TypeError("Transcript fields must be bytes")
    return len(value).to_bytes(4, "big") + value
    
def encode_transcript(fields):
    """
    Canonical transcript encoding.
    Every filed is length-prefixed with a 4-byte big-endian integer
    """
    return b"".join(encode_field(field) for field in fields)
    
def parse_transcript(data, expected_field_count):
    """
    Strictly parse a length-prefixed transcript
    Rejects:
     - Truncated length fields
     - Truncated filed values
     - incorrect lengths
     - trailing bytes
    """
    fields = []
    offset = 0
    
    for _ in range(expected_field_count):
        if len(data) - offset < 4:
            raise ValueError("Malformed transcript: missing field length")
            
        length = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        
        if length > len(data) - offset:
            raise ValueError("Malformed transcript: declared length exceeds data")
        
        field = data[offset:offset + length]
        offset += length
        fields.append(field)
    if offset != len(data):
        raise ValueError("Malformed transcript: trailing bytes")
    return fields
    
def generate_rsa_signing_key():
    """
    Generate a long-term 3072-bit RSA signing key.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def sign_handshake(private_key, role, transcript_hash):
    """
    Sign:
    role || SHA256(transcript)
    using RSA-PSS + SHA-256
    """
    message = role + transcript_hash
    
    return private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    
def verify_handshake(public_key, role, transcript_hash, signature):
    """
    Verify:
    role || SHA256(transcript)
    """
    message = role + transcript_hash
    
    try:
        public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        raise ValueError("Invalid RSA-PSS signature")
        
def load_ffdhe3072_group(filename):
    """
    Load the DH group generated during Lap Prep
    """
    with open(filename, "rb") as f:
        data = f.read()
        
    parameters = serialization.load_pem_parameters(data)
    
    if not isinstance(parameters, dh.DHParameters):
        raise ValueError("Group file does not contain DH parameters")
        
    numbers = parameters.parameter_numbers()
    
    if numbers.p.bit_length() != 3072:
        raise ValueError("Group is not 3072 bits; expected ffdhe3072")
    
    return parameters
    
@dataclass
class HandshakeMessage:
    sender_identity: bytes
    role: bytes
    ephemeral_public: bytes
    nonce: bytes
    transcript: bytes
    signature: bytes
    
class Party:
    def __init__(
        self, 
        identity, 
        role, 
        dh_parameters,
        signing_key,
        peer_identity,
        peer_public_key
    ):
        self.identity = identity
        self.role = role
        self.dh_parameters = dh_parameters
        
        self.signing_key = signing_key
        
        self.peer_identity = peer_identity 
        self.peer_public_key = peer_public_key
        
        self.dh_private = None
        self.dh_public = None
        self.nonce = None
        
        self.peer_dh_public = None
        self.peer_nonce = None
        self.transcript = None
        self.transcript_hash = None
        
        self.shared_secret = None
        self.keys = None
    
    def create_ephemeral_values(self):
        """
        Fresh DH private value and fresh 16-byte nonce
        """
        
        self.dh_private = (self.dh_parameters.generate_private_key())
        self.dh_public = self.dh_private.public_key()
        self.nonce = os.urandom(NONCE_SIZE)
    def public_value_bytes(self):
        y = self.dh_public.public_numbers().y
        return int_to_fixed_bytes(y)
    
    def build_transcript(
        self,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    ):
        fields = [
            PROTOCOL_LABEL, 
            GROUP_ID, 
            GATEWAY_ID, 
            NODE_ID,
            gateway_public,
            node_public,
            gateway_nonce,
            node_nonce
        ]
        
        transcript = encode_transcript(fields)
        
        parsed = parse_transcript(transcript, expected_field_count=8)
        
        if parsed != fields:
            raise ValueError("Transcript canonicalization failed")
        
        return transcript
        
    def create_message(
        self, 
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    ):
        self.transcript = self.build_transcript(
            gateway_public, 
            node_public,
            gateway_nonce,
            node_nonce
        )
        
        self.transcript_hash = sha256(self.transcript)
        
        signature = sign_handshake(
            self.signing_key, 
            self.role,
            self.transcript_hash
        )
        
        return HandshakeMessage(
            sender_identity = self.identity,
            role = self.role,
            ephemeral_public = self.public_value_bytes(),
            nonce = self.nonce,
            transcript = self.transcript, 
            signature = signature
        )
    def process_peer_message(
        self, 
        message,
        expected_gateway_public,
        expected_node_public,
        expected_gateway_nonce,
        expected_node_nonce
    ):
        if message.sender_identity != self.peer_identity:
            raise ValueError("Unexpected peer identity")
            
        if message.role == self.role:
            raise ValueError("Reflected handshake message rejected")
        
        expected_peer_role = (
            NODE_ROLE 
            if self.role == GATEWAY_ROLE
            else GATEWAY_ROLE
        )
        
        if message.role != expected_peer_role:
            raise ValueError("Unexpected peer role")
        if len(message.nonce) != NONCE_SIZE:
            raise ValueError("Invalid nonce length")
        if len(message.ephemeral_public) != FIELD_WIDTH:
            raise ValueError("Invalid DH public value length")
        
        fields = parse_transcript(message.transcript, expected_field_count = 8)
        (
            protocol_label,
            group_id, 
            gateway_identity, 
            node_identity,
            gateway_public,
            node_public,
            gateway_nonce,
            node_nonce
        ) = fields
        
        if protocol_label != PROTOCOL_LABEL:
            raise ValueError("Incorrect protocol label")
        if group_id != GROUP_ID:
            raise ValueError("Incorrect group identifier")
        if gateway_identity != GATEWAY_ID:
            raise ValueError("Unexpected gateway identity")
        if node_identity!= NODE_ID:
            raise ValueError("Unexpected node identity")
        if len(gateway_public) != FIELD_WIDTH:
            raise ValueError("Malformed gateway public value")
        if len(node_public) != FIELD_WIDTH:
            raise ValueError("Malformed node public value")
        if len(gateway_nonce) != NONCE_SIZE:
            raise ValueError("Malformed gateway nonce")
        if len(node_nonce) != NONCE_SIZE:
            raise ValueError("Malformed node nonce")
        
        if self.peer_identity == GATEWAY_ID:
            if message.ephemeral_public != gateway_public:
                raise ValueError("Gateway public value mismatch") 
            if message.nonce != gateway_nonce:
                raise ValueError("Gateway nonce mismatch")
        else:
            if message.ephemeral_public != node_public:
                raise ValueError("Node public value mismatch") 
            if message.nonce != node_nonce:
                raise ValueError("Node nonce mismatch")
        
        if self.identity == GATEWAY_ID:
            if gateway_public != self.public_value_bytes():
                raise ValueError("Our gateway public value changed")
            if gateway_nonce != self.nonce:
                raise ValueError("Our gateway nonce changed")
                
        else:
            if node_public != self.public_value_bytes():
                raise ValueError("Our node public value changed")
            if node_nonce != self.nonce:
                raise ValeuError("Our node nonce changed")
                
        transcript_hash = sha256(message.transcript)
        
        verify_handshake(
            self.peer_public_key, 
            message.role,
            transcript_hash,
            message.signature
        )
        
        peer_y = int.from_bytes(message.ephemeral_public, "big")
        p = self.dh_parameters.parameter_numbers().p
        
        if not(2 <= peer_y <= p -2):
            raise ValueError("Invalid DH public value")
            
        peer_public_numbers = dh.DHPublicNumbers(peer_y, self.dh_parameters.parameter_numbers())
        
        self.peer_dh_public = (peer_public_numbers.public_key())
        
        self.peer_nonce = message.nonce
        self.transcript = message.transcript
        self.transcript_hash = transcript_hash
        
        self.shared_secret = self.dh_private.exchange(self.peer_dh_public)
        self.keys = derive_session_keys(self.shared_secret, self.transcript_hash)
        
        return True

def derive_session_keys(Z, transcript_hash):
    z_integer = int.from_bytes(Z, "big")
    z_fixed = int_to_fixed_bytes(z_integer)
    
    K_master = sha256(b"CSCE465-KDF-v1" + z_fixed + transcript_hash)
    K_g2n_enc = hmac_sha256(K_master, b"gateway-to-node encryption" + transcript_hash)
    K_g2n_mac = hmac_sha256(K_master, b"gateway-to-node MAC" + transcript_hash)
    K_n2g_enc = hmac_sha256(K_master, b"node-to-gateway encryption" + transcript_hash)
    K_n2g_mac = hmac_sha256(K_master, b"node-to-gateway MAC" + transcript_hash)
    session_id = hmac_sha256(K_master, b"session identifier" + transcript_hash)[:8]
    
    return {
        "K_master": K_master,
        "K_g2n_enc": K_g2n_enc,
        "K_g2n_mac": K_g2n_mac,
        "K_n2g_enc": K_n2g_enc,
        "K_n2g_mac": K_n2g_mac,
        "session_id": session_id,
    }

def run_handshake(group_file):
    print("Loading ffdhe3072 group...")
    parameters = load_ffdhe3072_group(group_file)
    
    print("Generating long-term RSA signing keys...")
    gateway_rsa = generate_rsa_signing_key()
    node_rsa = generate_rsa_signing_key()
    
    gateway = Party(
        identity = GATEWAY_ID,
        role = GATEWAY_ROLE,
        dh_parameters = parameters,
        signing_key = gateway_rsa, 
        peer_identity = NODE_ID,
        peer_public_key = node_rsa.public_key()
    )
    
    node = Party(
        identity = NODE_ID,
        role = NODE_ROLE,
        dh_parameters = parameters,
        signing_key = node_rsa, 
        peer_identity = GATEWAY_ID,
        peer_public_key = gateway_rsa.public_key()
    )
    
    gateway.create_ephemeral_values()
    node.create_ephemeral_values()
    
    gateway_public = gateway.public_value_bytes()
    node_public = node.public_value_bytes()
    
    gateway_nonce = gateway.nonce
    node_nonce = node.nonce
    
    print()
    print("=== Fresh Session Values ===")
    print("Gateway DH public:", gateway_public.hex())
    print("Node DH public:", node_public.hex())    
    print("Gateway nonce:", gateway_nonce.hex())    
    print("Node nonce:", node_nonce.hex())
    
    gateway_message = gateway.create_message(
        gateway_public, 
        node_public,
        gateway_nonce,
        node_nonce
    )
    
    node.process_peer_message(
        gateway_message, 
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )
    
    node_message = node.create_message(
        gateway_public, 
        node_public,
        gateway_nonce,
        node_nonce
    )
    
    gateway.process_peer_message(
        node_message, 
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )
    
    if gateway.keys["K_master"] != node.keys["K_master"]:
        raise ValueError("Key agreement failed: K_master differs")
    if gateway.keys["K_g2n_enc"] != node.keys["K_g2n_enc"]:
        raise ValueError("Gateway-to-node encryption key differs")
    if gateway.keys["K_g2n_mac"] != node.keys["K_g2n_mac"]:
        raise ValueError("Gateway-to-node MAC key differs")
    if gateway.keys["K_n2g_enc"] != node.keys["K_n2g_enc"]:
        raise ValueError("Node-to-gateway encryption key differs")
    if gateway.keys["K_n2g_mac"] != node.keys["K_n2g_mac"]:
        raise ValueError("Node-to-gateway MAC key differs")
    if gateway.keys["session_id"] != node.keys["session_id"]:
        raise ValueError("Session IDs differ")
    
    print()
    print("=== Handshake Successful ===")
    print("Transcript hash:", gateway.transcript_hash.hex())
    print("Session ID:", gateway.keys["session_id"].hex()) 
    print()
    print("K_master:", gateway.keys["K_master"].hex()) 
    print("G->N enc key:", gateway.keys["K_g2n_enc"].hex()) 
    print("G->N MAC key:", gateway.keys["K_g2n_mac"].hex()) 
    print("N->G enc key:", gateway.keys["K_n2g_enc"].hex()) 
    print("N->G MAC key:", gateway.keys["K_n2g_mac"].hex()) 
    
    return gateway, node
    
GROUP_FILE = "ffdhe3072.pem"
if __name__ == "__main__":
    run_handshake(GROUP_FILE)





