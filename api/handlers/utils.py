from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from api.conf import AES_KEY

key = AES_KEY
key_bytes = bytes(key, "utf-8")
#print("Key: " + key)


#Creating Encryption function and using CBC mode because is very secure:

def my_encrypt(var1):

    aes_cipher = Cipher(algorithms.AES(key_bytes),modes.CBC(),backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    plaintext = var1
    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_encryptor.update(plaintext_bytes) + aes_encryptor.finalize()
    ciphertext = ciphertext_bytes.hex()
    return ciphertext
   

#Creating Decryption function using CBC mode because is very secure:
def decrypt(ciphertext_bytes):
    aes_cipher = Cipher(algorithms.AES(key_bytes),modes.CBC(),backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    plaintext_bytes_2 = aes_decryptor.update(ciphertext_bytes) + aes_decryptor.finalize()
    plaintext_2 = str(plaintext_bytes_2, "utf-8")
    return plaintext_2
   

#Creating Hash function with SHA256. The author intend using Scrypt /PBKDF instead if time permit
def hash_pass(message):
    digest_sha256 = hashes.Hash(hashes.SHA256())
    digest_sha256.update(message)
    hash_sha256 = digest_sha256.finalize()
    return hash_sha256.hex()
   



# The author intend to use this to hash the passphrase if time permit
#import os
# from cryptopgraphy.hazmat.primitives.kdf.scrypt import Scrypt

#def my_scrypt(message):
# salt = os.urandom(16) #Using 256-bit salt value
# ola_n=2**22 # This is to make the computation very difficult
# kdf = Scrypt(salt=salt, length=32, n=ola_n, r=8, p=1)
# passphrase = input("please enter your passphrase:")
# passphrase_bytes = bytes(passphrase, "utf-8")
# hashed_passphrase = kdf.derive(passphrase_bytes)
 


