import streamlit as st
import io
import os

st.header("Block Cipher with File Encryption")

def get_file_extension(file_name):
    _, extension = os.path.splitext(file_name)
    return extension

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > len(data):
        raise ValueError("Invalid padding encountered.")
    return data[:-padding_length]

def xor_encrypted_block(plaintext_block, key):
    return bytes([b ^ k for b, k in zip(plaintext_block, key * (len(plaintext_block) // len(key) + 1))])

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for i in range(0, len(padded_plaintext), block_size):
        plaintext_block = padded_plaintext[i:i + block_size]
        encrypted_block = xor_encrypted_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for i in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[i:i + block_size]
        decrypted_block = xor_encrypted_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    return unpad(decrypted_data)

def encrypt_file(file_bytes, key, block_size):
    return xor_encrypt(file_bytes, key, block_size)

def decrypt_file(file_bytes, key, block_size):
    return xor_decrypt(file_bytes, key, block_size)

def main():
    st.subheader("File Encryption")
    uploaded_file = st.file_uploader("Choose a file to encrypt")
    key = st.text_input("Enter key:")
    block_size = st.number_input("Enter block size:", value=16, min_value=8, max_value=128, step=1)

    if st.button("Encrypt"):
        if uploaded_file is not None and key:
            key_bytes = bytes(key.encode())
            key_padded = pad(key_bytes, block_size)
            encrypted_data = encrypt_file(uploaded_file.getvalue(), key_padded, block_size)
            st.download_button("Download Encrypted File", encrypted_data, file_name="encrypted_file")
            st.success("Encryption successful!")
        else:
            st.error("Please upload a file and provide a key.")

    if st.button("Decrypt"):
        if uploaded_file is not None and key:
            key_bytes = bytes(key.encode())
            key_padded = pad(key_bytes, block_size)
            decrypted_data = decrypt_file(uploaded_file.getvalue(), key_padded, block_size)
            st.download_button("Download Decrypted File", decrypted_data, file_name=uploaded_file.name)
            st.success("Decryption successful!")
        else:
            st.error("Please upload a file and provide a key.")

if __name__ == "__main__":
    main()
