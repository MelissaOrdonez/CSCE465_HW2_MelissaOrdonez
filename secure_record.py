import struct
import hmac

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1

DIRECTION_GATEWAY_TO_NODE = 0
DIRECTION_NODE_TO_GATEWAY = 1

HEADER_SIZE = 1+1+8+1+4
IV_SIZE = 16
TAG_SIZE = 32

class RecordError(Exception):
    pass
    
class SecureRecord:
    def __init__(self, session_keys, direction):
        if direction not in (DIRECTION_GATEWAY_TO_NODE, DIRECTION_NODE_TO_GATEWAY):
            raise ValueError("Invalid direction")
            
        self.direction = direction
        
        if direction == DIRECTION_GATEWAY_TO_NODE:
            self.k_enc = session_keys["K_g2n_enc"]
            self.k_mac = session_keys["K_g2n_mac"]
        else:
            self.k_enc = session_keys["K_n2g_enc"]
            self.k_mac = session_keys["K_n2g_mac"]
        
        self.session_id = session_keys["session_id"]
        
        if len(self.k_enc) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        if len(self.k_mac) != 32:
            raise ValueError("MAC key must be 32 bytes")
        if len(self.session_id) != 8:
            raise ValueError("Session ID must be 8 bytes")
        
        self.send_sequence = 0
        self.receive_sequence = 0
        
    def seal(self, message_type, plaintext):
        if not isinstance(message_type, int):
            raise TypeError("message_type must be an integer")
        if not 0 <= message_type <= 255:
            raise ValueError("message_type must fit in one byte")
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
            
        sequence = self.send_sequence
        
        ciphertext_length = len(plaintext)
        
        header = struct.pack(
            ">BBQBI",
            VERSION,
            self.direction,
            sequence,
            message_type,
            ciphertext_length
        )
        
        iv = self.session_id + sequence.to_bytes(8, "big")
        
        if len(iv) != IV_SIZE:
            raise ValueError("IV must be 16 bytes")
            
        cipher = Cipher(
            algorithms.AES(self.k_enc),
            modes.CTR(iv)
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        h = crypto_hmac.HMAC(self.k_mac, hashes.SHA256())
        h.update(header)
        h.update(iv)
        h.update(ciphertext)
        
        tag = h.finalize()
        self.send_sequence += 1
        
        return header + iv + ciphertext + tag
    
    def open_record(self, record):
        if not isinstance(record, bytes):
            raise RecordError("Record must be bytes")
        if len(record) < HEADER_SIZE + IV_SIZE + TAG_SIZE:
            raise RecordError("Record is too short")
        
        header = record[:HEADER_SIZE]
        try:
            (
                version,
                direction,
                sequence,
                message_type,
                ciphertext_length
            ) = struct.unpack(
                ">BBQBI",
                header,
            )
        except struct.error as exc:
            raise RecordError("Malformed header") from exc
        
        if version != VERSION:
            raise RecordError("Unsupported protocol version")
        if direction != self.direction:
            raise RecordError("Wrong record direction")
        if sequence != self.receive_sequence:
            raise RecordError(
                f"Unexpected sequence number: "
                f"expected {self.receive_sequence}, got{sequence}"
            )
            
        expected_length = (
            HEADER_SIZE
            + IV_SIZE
            + ciphertext_length
            + TAG_SIZE
        )
        
        if len(record) != expected_length:
            raise RecordError("Invalid ciphertext length")
        
        iv_start = HEADER_SIZE
        iv_end = iv_start + IV_SIZE
        
        ciphertext_start = iv_end
        ciphertext_end = ciphertext_start + ciphertext_length
        
        tag_start = ciphertext_end
        
        iv = record[iv_start:iv_end]
        ciphertext = record[ciphertext_start:ciphertext_end]
        tag = record[tag_start:]
        
        expected_iv = (self.session_id + sequence.to_bytes(8, "big"))
        
        if not hmac.compare_digest(iv, expected_iv):
            raise RecordError("Invalid IV")
        
        h = crypto_hmac.HMAC(self.k_mac, hashes.SHA256())
        h.update(header)
        h.update(iv)
        h.update(ciphertext)
        
        try:
            h.verify(tag)
        except Exception as exc:
            raise RecordError("Invalid MAC") from exc
            
        cipher = Cipher(algorithms.AES(self.k_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        
        try:
            plaintext = (decryptor.update(ciphertext) + decryptor.finalize())
        except Exception as exc:
            raise RecordError("Decryption failed") from exc
        
        self.receive_sequence += 1
        return plaintext
        

        
