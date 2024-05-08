import streamlit as st
import hashlib

st.header("XOR Cipher")

plaintext = bytes(st.text_input("Plain Text:").encode())
key_input = st.text_input("Key:")

# Use hashlib to hash the key input
key_hash = hashlib.sha256(key_input.encode()).digest()

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ key[i % len(key)])
    
    return ciphertext  

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)

if st.button("Submit"): 
    if not key_input:
        st.error("Invalid key")
    else:
        # Use the hashed key
        if not(1 < len(plaintext) >= len(key_hash) >= 1):
            st.write("Plaintext length should be equal or greater than the length of key")
        elif not plaintext != key_hash: 
            st.write("Plaintext should not be equal to the key")
    
        else: 
            cipher_text = xor_encrypt(plaintext, key_hash)
            st.write("Ciphertext:", cipher_text.decode())
    
            decryption =  xor_decrypt(cipher_text, key_hash)
            st.write("Decrypted:", decryption.decode())
