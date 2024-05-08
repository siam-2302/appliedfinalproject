import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Cryptographic Algorithms",
        page_icon="🔒",
    )

    st.title("Welcome to our Cryptographic Algorithms Repository! 👋")
    st.write("BY: Christian Siam Busadre, Jerome Llaban, and Mae Julienn Arbo Mata")
    st.write("BSCS 3A")

    st.markdown(
        """
        Here you can select from a variety of cryptographic algorithms:
        - **[XOR Cipher](#xor-cipher):** A symmetric encryption algorithm using bitwise XOR operation.
        - **[Caesar Cipher](#caesar-cipher):** A simple encryption method shifting each letter by a fixed number.
        - **[Primitive Root](#primitive-root):** A mathematical concept used in certain cryptographic algorithms.
        - **[Block Cipher](#block-cipher):** A symmetric key cryptographic algorithm operating on fixed-length blocks.
        - **[SHA-1](#sha-1):** A cryptographic hash function producing a 160-bit hash value.
        """
    )

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
        
        **Process:**
        1. Take the plaintext and a shift key as input.
        2. Shift each letter in the plaintext by the specified number of places.
        3. Output the resulting ciphertext.
        """)

    with st.expander("Primitive Root"):
        st.write("""
        **Description:** A primitive root is a mathematical concept used in certain cryptographic algorithms, particularly in the context of modular arithmetic.
        
        **Process:**
        1. Find all possible primitive roots modulo a given prime number.
        2. Verify if a specific number is a primitive root modulo the given prime.
        """)

    with st.expander("Block Cipher"):
        st.write("""
        **Description:** A block cipher is a symmetric key cryptographic algorithm that operates on fixed-length blocks of data.
        
        **Process:**
        1. Divide the plaintext into fixed-size blocks.
        2. Apply encryption or decryption operation to each block using a specified key.
        3. Output the resulting ciphertext or plaintext.
        """)

    with st.expander("SHA-1"):
        st.write("""
        **Description:** SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit hash value known as a message digest.
        
        **Process:**
        1. Take the input message as a sequence of bytes.
        2. Pad the message to ensure its length is a multiple of 512 bits.
        3. Process the message in 512-bit blocks.
        4. Output the resulting hash value.
        """)


if __name__ == "__main__":
    run()
