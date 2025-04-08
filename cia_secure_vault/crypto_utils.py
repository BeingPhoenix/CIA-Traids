# crypto_utils.py
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Constants
KEY_SIZE = 32         # 256-bit AES key
SALT_SIZE = 16        # 16 bytes salt
IV_SIZE = 16          # 16 bytes IV for AES
PBKDF2_ITERATIONS = 100000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from the password and salt."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_file(input_file: str, output_file: str, password: str) -> bytes:
    """
    Encrypt a file using AES-CBC.
    The output file contains: salt (16 bytes) + IV (16 bytes) + ciphertext.
    Returns the encryption key used (to be used for HMAC later).
    """
    # Read plaintext from file
    with open(input_file, "rb") as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    with open(output_file, "wb") as f:
        f.write(salt + iv + ciphertext)
    
    return key

def decrypt_file(input_file: str, output_file: str, password: str) -> bytes:
    """
    Decrypt a file that was encrypted with encrypt_file.
    Reads salt, IV, ciphertext from the file.
    Returns the decryption key used (so you can verify integrity).
    """
    with open(input_file, "rb") as f:
        file_data = f.read()

    if len(file_data) < SALT_SIZE + IV_SIZE:
        raise ValueError("File data is too short!")

    salt = file_data[:SALT_SIZE]
    iv = file_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = file_data[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(output_file, "wb") as f:
        f.write(plaintext)
    
    return key
