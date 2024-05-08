import streamlit as st

st.header("XOR Cipher")

def xor_encrypt_text(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ key[i % len(key)])
    return ciphertext

def xor_decrypt_text(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt_text(ciphertext, key)

def main():
    plaintext = st.text_input("Enter Plain Text:")
    key = st.text_input("Enter Key:")

    if st.button("Encrypt"):
        if plaintext and key:
            plaintext_bytes = plaintext.encode()
            key_bytes = key.encode()
            encrypted_text = xor_encrypt_text(plaintext_bytes, key_bytes)
            st.write("Encrypted Text:", encrypted_text.decode())
        else:
            st.error("Please enter both plain text and key.")

    if st.button("Decrypt"):
        if plaintext and key:
            ciphertext = bytes.fromhex(plaintext)  # Assuming ciphertext is entered in hexadecimal format
            key_bytes = key.encode()
            decrypted_text = xor_decrypt_text(ciphertext, key_bytes)
            st.write("Decrypted Text:", decrypted_text.decode())
        else:
            st.error("Please enter both cipher text and key.")

if __name__ == "__main__":
    main()
