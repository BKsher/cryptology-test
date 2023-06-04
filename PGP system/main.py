from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import rsa
import zlib

# Compression
def compress_message(message):
    return zlib.compress(message.encode())

# Decompression
def decompress_message(compressed_message):
    return zlib.decompress(compressed_message).decode()

# Symmetric-Key Encryption
def aes_encrypt(compressed_message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    return cipher.iv, cipher.encrypt(pad(compressed_message, AES.block_size))

# Symmetric-Key Decryption
def aes_decrypt(iv, encrypted_message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(encrypted_message), AES.block_size)

# Public-Key Encryption
def rsa_encrypt(aes_key, rsa_pub_key):
    return rsa.encrypt(aes_key, rsa_pub_key)

# Public-Key Decryption
def rsa_decrypt(encrypted_aes_key, rsa_priv_key):
    return rsa.decrypt(encrypted_aes_key, rsa_priv_key)

# Digital Signature
def sign(message, rsa_priv_key):
    return rsa.sign(message.encode(), rsa_priv_key, 'SHA-256')

# Verification
def verify(message, signature, rsa_pub_key):
    try:
        rsa.verify(message.encode(), signature, rsa_pub_key)
        return True
    except rsa.VerificationError:
        return False

# Generate an RSA key pair
(pub_key, priv_key) = rsa.newkeys(2048)

# Original message
message = "The secret message"

# Digital Signature
signature = sign(message, priv_key)

# Compression
compressed_message = compress_message(message)

# Generate a random AES key
aes_key = get_random_bytes(16)

# Symmetric-Key Encryption
iv, encrypted_message = aes_encrypt(compressed_message, aes_key)

# Public-Key Encryption
encrypted_aes_key = rsa_encrypt(aes_key, pub_key)

# Send 'encrypted_message', 'encrypted_aes_key' and 'signature' to the recipient

# At the recipient side:

# Public-Key Decryption
decrypted_aes_key = rsa_decrypt(encrypted_aes_key, priv_key)

# Symmetric-Key Decryption
decompressed_message_bytes = aes_decrypt(iv, encrypted_message, decrypted_aes_key)

# Decompression
decompressed_message = decompress_message(decompressed_message_bytes)

# Verification
if verify(message, signature, pub_key):
    print("The signature is valid.")
else:
    print("The signature is invalid.")

print("Decrypted and decompressed message:", decompressed_message)
