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
   

#Creating Hash function with SHA256. The author intend using PBKDFhere
def hash_pass(message):
    digest_sha256 = hashes.Hash(hashes.SHA256())
    digest_sha256.update(message)
    hash_sha256 = digest_sha256.finalize()
    return hash_sha256.hex()
   
 


