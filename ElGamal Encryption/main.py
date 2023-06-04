from Crypto.Util import number
import secrets
from sympy import isprime, mod_inverse

# Converts the text message into its ASCII representation
def text_to_int(text):
    return [ord(c) for c in text]

# Converts ASCII values back into text
def int_to_text(ints):
    return ''.join(chr(i) for i in ints)

# Function to find a primitive root for a given prime number
def find_primitive(root):
    if not isprime(root):
        return -1
    else:
        # Check for a number 'g' whose powers (mod 'root') generate all numbers from 1 to root-1
        for i in range(2, root):
            powers = [pow(i, power, root) for power in range(1, root)]
            if len(set(powers)) == root - 1:
                return i

# Key generation function for ElGamal
def ElGamal_keygen(size):
    # Generate a prime number of 'size' bits
    root = number.getPrime(size)
    # Find a primitive root for the generated prime number
    g = find_primitive(root)
    # Generate the private key (a random number less than 'root')
    priv_key = secrets.randbelow(root - 1) + 1
    # Generate the public key (g^priv_key mod root)
    pub_key = pow(g, priv_key, root)
    return root, g, pub_key, priv_key

# ElGamal encryption function
def ElGamal_encrypt(root, g, pub_key, msg):
    # Generate an ephemeral key 'k'
    k = secrets.randbelow(root - 1) + 1
    # Convert the message into its ASCII representation
    msg = text_to_int(msg)
    # Each ASCII value is encrypted into two parts and returned
    cipher = [(pow(g, k, root), m * pow(pub_key, k, root) % root) for m in msg]
    return cipher

# ElGamal decryption function
def ElGamal_decrypt(root, cipher, priv_key):
    # Each ASCII value is decrypted and returned
    msg = [c[1] * mod_inverse(pow(c[0], priv_key, root), root) % root for c in cipher]
    # Convert the ASCII values back into text
    return int_to_text(msg)

# Generate the keys for ElGamal
root, g, pub_key, priv_key = ElGamal_keygen(16)

# Original message
msg = "The secrect message"
print("Original message:", msg)

# Encryption
cipher = ElGamal_encrypt(root, g, pub_key, msg)
print("Ciphertext:", cipher)

# Decryption
print("Decrypted message:", ElGamal_decrypt(root, cipher, priv_key))
