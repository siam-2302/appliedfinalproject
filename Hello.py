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

    with st.expander("Caesar Cipher"):
        st.write("""
        **Description:** The Caesar cipher is a simple encryption method where each letter in the plaintext is shifted by a fixed number of places down the alphabet.
        
        **Pseudocode:**
        ```
        function caesar_encrypt_decrypt(text, shift_keys, ifdecrypt):
            result = ""
            transformations = []
            
            for i, char in enumerate(text):
                shift_key = shift_keys[i % len(shift_keys)]
                
                if 32 <= ord(char) <= 125:
                    new_ascii = ord(char) + shift_key if not ifdecrypt else ord(char) - shift_key
                        
                    while new_ascii > 125:
                        new_ascii -= 94
                    while new_ascii < 32:
                        new_ascii += 94
                        
                    result += chr(new_ascii)
                    transformations.append((char, shift_key, chr(new_ascii)))
                else:
                    result += char
                    transformations.append((char, "", char))
            return result, transformations
        ```
        
        **Process:**
        1. Take the plaintext and a shift key as input.
        2. Shift each letter in the plaintext by the specified number of places.
        3. Output the resulting ciphertext.
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

        st.header("File Encryption and Decryption")

        # Initialize cipher suite in session state
        if 'cipher_suite' not in st.session_state:
            key, st.session_state.cipher_suite = generate_key()

        uploaded_file = st.file_uploader("Choose a file to encrypt", type=None)

        if uploaded_file:
            file_data = uploaded_file.read()
            if st.button("Encrypt File"):
                encrypted_data = encrypt_file(file_data, st.session_state.cipher_suite)
                st.success("File encrypted successfully!")
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name=f"{uploaded_file.name}.enc",
                    mime="application/octet-stream"
                )

        encrypted_file = st.file_uploader("Choose an encrypted file to decrypt", type=["enc"])

        if encrypted_file:
            encrypted_file_data = encrypted_file.read()
            if st.button("Decrypt File"):
                try:
                    decrypted_data = decrypt_file(encrypted_file_data, st.session_state.cipher_suite)
                    st.success("File decrypted successfully!")
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_data,
                        file_name=encrypted_file.name.replace(".enc", ""),
                        mime="application/octet-stream"
                    )
                except Exception as e:
                    st.error(f"An error occurred during decryption: {str(e)}")

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

        st.header("Hashing")

        # Input box for the string to hash
        input_string = st.text_input("Enter a string:")

        # Select box for the hashing method
        hash_method = st.selectbox("Select a hashing method:", ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'])

        # Compute the hash when the button is clicked
        if st.button("Hash"):
            if input_string:
                hashed_text = hash_string(input_string, method=hash_method)
                st.success(f"The {hash_method} hash of '{input_string}' is: {hashed_text}")
            else:
                st.error("Please enter a string.")

if __name__ == "__main__":
    run()
