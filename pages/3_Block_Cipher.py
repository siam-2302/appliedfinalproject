import streamlit as st
import hashlib

st.header("Block Cipher")

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def xor_encrypted_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block

def xor_decrypted_block(ciphertext_block, key):
    return xor_encrypted_block(ciphertext_block, key)

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i + block_size]
        encrypted_block = xor_encrypted_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for x, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i + block_size]
        decrypted_block = xor_decrypted_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

def main():
    encryption_option = st.radio("Choose encryption mode:", ("Text Input", "File Upload"))
    if encryption_option == "Text Input":
        plaintext = st.text_input("Enter plaintext:")
        key = st.text_input("Enter key:")
        block_size = st.number_input("Enter block size:", value=16, step=1)
        if st.button("Encrypt"):
            plaintext_bytes = bytes(plaintext.encode())
            key_bytes = bytes(key.encode())
            if block_size not in [8, 16, 32, 64, 128]:
                st.error('Block size must be one of 8, 16, 32, 64, or 128 bytes')
            else:
                key_padded = pad(key_bytes, block_size)
                encrypted_data = xor_encrypt(plaintext_bytes, key_padded, block_size)
                st.write("Encrypted data:", encrypted_data.hex())
    elif encryption_option == "File Upload":
        uploaded_file = st.file_uploader("Upload a file")
        key = st.text_input("Enter key:")
        block_size = st.number_input("Enter block size:", value=16, step=1)
        if uploaded_file is not None:
            file_contents = uploaded_file.getvalue()
            if st.button("Encrypt File"):
                key_bytes = bytes(key.encode())
                if block_size not in [8, 16, 32, 64, 128]:
                    st.error('Block size must be one of 8, 16, 32, 64, or 128 bytes')
                else:
                    key_padded = pad(key_bytes, block_size)
                    encrypted_data = xor_encrypt(file_contents, key_padded, block_size)
                    st.write("Encrypted data:", encrypted_data.hex())

if __name__ == "__main__":
    main()
