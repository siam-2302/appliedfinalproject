import streamlit as st
import io

st.header("Block Cipher with File Encryption")

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

def process_file(file, key, block_size):
    # Read the file content
    file_bytes = file.getvalue()
    # Encrypt
    encrypted_data = xor_encrypt(file_bytes, key, block_size)
    # Decrypt
    decrypted_data = xor_decrypt(encrypted_data, key, block_size)
    return encrypted_data, decrypted_data

def main():
    st.subheader("File Encryption")
    uploaded_file = st.file_uploader("Choose a file to encrypt")
    key = st.text_input("Enter key:")
    block_size = st.number_input("Enter block size:", value=16, min_value=8, max_value=128, step=1)

    if st.button("Encrypt & Decrypt"):
        if uploaded_file is not None and key:
            key_bytes = bytes(key.encode())
            key_padded = pad(key_bytes, block_size)
            encrypted_data, decrypted_data = process_file(uploaded_file, key_padded, block_size)
            
            # Show outputs
            st.download_button("Download Encrypted File", encrypted_data, file_name="encrypted_file")
            st.download_button("Download Decrypted File", decrypted_data, file_name="decrypted_file")

            st.success("Encryption and decryption successful!")
        else:
            st.error("Please upload a file and provide a key.")

if __name__ == "__main__":
    main()
