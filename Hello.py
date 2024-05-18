import streamlit as st
from cryptography.fernet import Fernet
from streamlit.logger import get_logger
import hashlib

LOGGER = get_logger(__name__)

# Function to generate a key and instantiate a Fernet instance
def generate_key():
    key = Fernet.generate_key()
    return key, Fernet(key)

# Function to encrypt text
def encrypt_text(text, cipher_suite):
    return cipher_suite.encrypt(text.encode())

# Function to decrypt text
def decrypt_text(encrypted_text, cipher_suite):
    return cipher_suite.decrypt(encrypted_text).decode()

# Function to encrypt file
def encrypt_file(file_data, cipher_suite):
    return cipher_suite.encrypt(file_data)

# Function to decrypt file
def decrypt_file(encrypted_data, cipher_suite):
    return cipher_suite.decrypt(encrypted_data)

# Define the hashing function
def hash_string(text, method='md5'):
    methods = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256,
        'SHA-512': hashlib.sha512
    }

    if method.upper() not in methods:
        raise ValueError("Invalid hashing method. Choose from MD5, SHA-1, SHA-256, SHA-512.")

    hash_object = methods[method.upper()]()
    hash_object.update(text.encode())
    return hash_object.hexdigest()

def run():
    st.set_page_config(
        page_title="Cryptographic Algorithms",
        page_icon="🔒",
    )

    st.title("Welcome to our Final Project in Applied Cryptography! 👋")
    st.write("BY: Christian Siam Busadre, Jerome Llaban, and Mae Julienn Arbo Mata")
    st.write("BSCS 3A")

    with st.expander("XOR Cipher"):
        st.write("""
        **Description:** The XOR cipher is a symmetric encryption algorithm that works by performing an exclusive OR (XOR) operation between the plaintext and a key.
        
        **Pseudocode:**
        ```
        function xor_encrypt(plaintext, key):
            ciphertext = ""
            for i in range(len(plaintext)):
                ciphertext += chr(ord(plaintext[i]) ^ ord(key[i % len(key)]))
            return ciphertext
        ```
        
        **Process:**
        1. Take the plaintext and key as input.
        2. Perform XOR operation between each character of the plaintext and the corresponding character of the key.
        3. Output the resulting ciphertext.
        """)

    with st.expander("Symmetric Encryption and Decryption"):
        st.write("""
        **Description:** This application allows you to encrypt and decrypt files using symmetric encryption. 
        You can upload a file to encrypt it and then download the encrypted version. 
        Similarly, you can upload an encrypted file to decrypt it back to its original form.
        
        **Pseudocode:**
        ```
        1. Generate a key and create a cipher suite
            key, cipher_suite = generate_key()
        
        2. Encrypt a file
            a. Read the file data
            b. Encrypt the file data using the cipher suite
            c. Provide an option to download the encrypted file
        
        3. Decrypt a file
            a. Read the encrypted file data
            b. Decrypt the file data using the cipher suite
            c. Provide an option to download the decrypted file
        ```
        
        **Process:**
        1. **Upload a File to Encrypt**: Select a file from your device to encrypt.
        2. **Encrypt the File**: Click the "Encrypt File" button to encrypt the uploaded file. 
           You will be able to download the encrypted file.
        3. **Upload an Encrypted File to Decrypt**: Select an encrypted file (with `.enc` extension) 
           from your device to decrypt.
        4. **Decrypt the File**: Click the "Decrypt File" button to decrypt the uploaded file. 
           You will be able to download the decrypted file.
        """)

    with st.expander("Primitive Root"):
        st.write("""
        **Description:** A primitive root is a mathematical concept used in certain cryptographic algorithms, particularly in the context of modular arithmetic.
        
        **Pseudocode:**
        ```
        function find_primitive_roots(p):
            primitive_roots = []
            for g in range(1, p):
                is_primitive_root = True
                powers = set()
                for j in range(1, p):
                    res = compute_modulus(g, j, p)
                    powers.add(res)
                    if res == 1:
                        break
                if len(powers) == p - 1:
                    primitive_roots.append(g)
            return primitive_roots
        ```
        
        **Process:**
        1. Find all possible primitive roots modulo a given prime number.
        2. Verify if a specific number is a primitive root modulo the given prime.
        """)

    with st.expander("Block Cipher"):
        st.write("""
        **Description:** A block cipher is a symmetric key cryptographic algorithm that operates on fixed-length blocks of data.
        
        **Pseudocode:**
        ```
        function block_cipher_encrypt_decrypt(plaintext, key, block_size):
            result = ""
            # Implement block cipher encryption or decryption algorithm
            return result
        ```
        
        **Process:**
        1. Divide the plaintext into fixed-size blocks.
        2. Apply encryption or decryption operation to each block using a specified key.
        3. Output the resulting ciphertext or plaintext.
        """)


    with st.expander("Hashing"):
        st.write("""
        **Description:** Hashing is a process of converting an input (or 'message') into a fixed-size string of bytes, typically a digest that is unique to each unique input. Hashing is used in various applications, including data integrity verification and cryptographic algorithms.
        
        **Pseudocode:**
        ```
        function hash_string(text, method):
            methods = {
                'MD5': hashlib.md5,
                'SHA-1': hashlib.sha1,
                'SHA-256': hashlib.sha256,
                'SHA-512': hashlib.sha512
            }

            if method.upper() not in methods:
                raise ValueError("Invalid hashing method. Choose from MD5, SHA-1, SHA-256, SHA-512.")

            hash_object = methods[method.upper()]()
            hash_object.update(text.encode())
            return hash_object.hexdigest()
        ```
        
        **Process:**
        1. Enter a string to be hashed.
        2. Select the hashing algorithm (e.g., MD5, SHA-1, SHA-256, SHA-512).
        3. Compute the hash of the entered string using the selected algorithm.
        4. Display the resulting hash.
        """)


if __name__ == "__main__":
    run()
