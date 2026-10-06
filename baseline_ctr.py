from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
    
def relay(ciphertext, original, modified):
    delta = xor_bytes(original, modified)
    print("\nOriginal XOR Modified")
    print(delta.hex())
    return xor_bytes(ciphertext, delta)
    
def receiver(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print("Reciever decoded:", plaintext.decode())
    return plaintext

def main():
    original = b'{"action":"READ","path":"notes.txt"}'
    modified = b'{"action":"SEND","path":"notes.txt"}'
        
    key = os.urandom(16)
    nonce = os.urandom(16)
        
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(original) + encryptor.finalize()
        
    print("\nOriginal Plaintext")
    print(original.decode())
    
    print("\nOriginal Text")
    print(original.hex())
    
    print("\nModified Text")
    print(modified.hex())
        
    print("\nOriginal Ciphertext:")
    print(ciphertext.hex())
    
    modified_ciphertext = relay(ciphertext, original, modified)
    
    print("\nModified Ciphertext:")
    print(modified_ciphertext.hex())
    
    print("\nCiphertext XOR modified ciphertext:")
    print(xor_bytes(ciphertext, modified_ciphertext).hex())
        
    print("\nReceiver First Attempt")
    receiver(key, nonce, modified_ciphertext)
    print("Receiver Second Attempt")
    receiver(key, nonce, modified_ciphertext)
        
if __name__ == "__main__":
    main()
