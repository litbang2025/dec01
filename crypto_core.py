from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    iv = b'\x00' * 16
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    padding_length = 16 - (len(data) % 16)
    data_padded = data + bytes([padding_length])*padding_length
    
    encrypted = encryptor.update(data_padded) + encryptor.finalize()
    return encrypted

def aes_decrypt(encrypted: bytes, key: bytes) -> bytes:
    iv = b'\x00' * 16
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length]
    
    return decrypted
