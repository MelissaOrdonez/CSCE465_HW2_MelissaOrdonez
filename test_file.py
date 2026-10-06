import pytest

from handshake import (
    run_handshake,
    generate_rsa_signing_key,
    load_ffdhe3072_group,
    Party,
    GATEWAY_ID,
    NODE_ID,
    GATEWAY_ROLE,
    NODE_ROLE
)

from secure_record import (
    SecureRecord,
    RecordError,
    DIRECTION_GATEWAY_TO_NODE,
    DIRECTION_NODE_TO_GATEWAY
)

GROUP_FILE = "ffdhe3072.pem"

@pytest.fixture
def session():
    return run_handshake(GROUP_FILE)

def test_valid_handshake_and_bidirectional_messages(session):
    gateway, node = session
    
    gateway_sender = SecureRecord(gateway.keys, DIRECTION_GATEWAY_TO_NODE)
    node_receiver = SecureRecord(node.keys, DIRECTION_GATEWAY_TO_NODE)
    
    record = gateway_sender.seal(1, b"Hello from gateway")
    
    assert node_receiver.open_record(record) == b"Hello from gateway"
    
    node_sender = SecureRecord(node.keys, DIRECTION_NODE_TO_GATEWAY)
    
    gateway_receiver = SecureRecord(gateway.keys, DIRECTION_NODE_TO_GATEWAY)
    
    record = node_sender.seal(2, b"Hello from node")
    
    assert gateway_receiver.open_record(record) == b"Hello from node"

def test_modified_ciphertext(session):
    gateway, node = session
    
    sender = SecureRecord(gateway.keys, DIRECTION_GATEWAY_TO_NODE)
    receiver = SecureRecord(node.keys, DIRECTION_GATEWAY_TO_NODE)
    
    record = bytearray(sender.seal(1, b"Secret"))
    
    record[31] ^= 1
    
    with pytest.raises(RecordError, match = "Invalid MAC"):
        receiver.open_record(bytes(record))
        
    assert receiver.receive_sequence == 0
    
def test_modified_header(session):
    gateway, node = session
    
    sender = SecureRecord(gateway.keys, DIRECTION_GATEWAY_TO_NODE)
    receiver = SecureRecord(node.keys, DIRECTION_GATEWAY_TO_NODE)
    
    record = bytearray(sender.seal(1, b"Secret"))
    
    record[10] ^= 1
    
    with pytest.raises(RecordError, match = "Invalid MAC"):
        receiver.open_record(bytes(record))
        
    assert receiver.receive_sequence == 0
    
def test_replay(session):
    gateway, node = session
    
    sender = SecureRecord(gateway.keys, DIRECTION_GATEWAY_TO_NODE)
    receiver = SecureRecord(node.keys, DIRECTION_GATEWAY_TO_NODE)
    
    record = sender.seal(1, b"Secret")
    
    assert receiver.open_record(record) == b"Secret"
    assert receiver.receive_sequence == 1
    
    with pytest.raises(RecordError, match = "Unexpected sequence number"):
        receiver.open_record(record)
        
    assert receiver.receive_sequence == 1
    
def test_reflected_record(session):
    gateway, node = session
    
    sender = SecureRecord(gateway.keys, DIRECTION_GATEWAY_TO_NODE)
    opposite_receiver = SecureRecord(gateway.keys, DIRECTION_NODE_TO_GATEWAY)
    
    record = sender.seal(1, b"Secret")
    
    with pytest.raises(RecordError, match = "Wrong record direction"):
        opposite_receiver.open_record(record)
        
    assert opposite_receiver.receive_sequence == 0
    
def test_invalid_rsa_signature():
    parameters = load_ffdhe3072_group(GROUP_FILE)
    
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
    
    gateway_message = gateway.create_message(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )
    
    bad_signature = bytearray(gateway_message.signature)
    
    bad_signature[0] ^= 1
    
    gateway_message.signature = bytes(bad_signature)
    
    with pytest.raises(ValueError, match="Invalid RSA-PSS signature"):
        node.process_peer_message(
            gateway_message,
            gateway_public,
            node_public,
            gateway_nonce,
            node_nonce
        )
    
    assert node.keys is None
