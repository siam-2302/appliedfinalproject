import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


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


if __name__ == "__main__":
    run()
