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
    st.write("Encrypted blocks")
    for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i + block_size]
        st.write(f"Plain  block[{x}]: {plaintext_block.hex()} : {plaintext_block}")
        encrypted_block = xor_encrypted_block(plaintext_block, key)
        encrypted_data += encrypted_block
        st.write(f"Cipher block[{x}]: {encrypted_block.hex()} : {encrypted_block}")
    return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    st.write("Decrypted blocks")
    for x, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i + block_size]
        decrypted_block = xor_decrypted_block(ciphertext_block, key)
        decrypted_data += decrypted_block
        st.write(f"block[{x}]: {decrypted_block.hex()}: {decrypted_block}")
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

def main():
    plaintext = st.text_input("Enter plaintext:")
    key = st.text_input("Enter key:")
    block_size = st.number_input("Enter block size:", value=16, step=1)
    if st.button("submit"):
        plaintext_bytes = bytes(plaintext.encode())
        key_bytes = bytes(key.encode())
        if block_size not in [8, 16, 32, 64, 128]:
            st.error('Block size must be one of 8, 16, 32, 64, or 128 bytes')
        else:
            key_padded = pad(key_bytes, block_size)
            encrypted_data = xor_encrypt(plaintext_bytes, key_padded, block_size)
            decrypted_data = xor_decrypt(encrypted_data, key_padded, block_size)
            st.write("\nOriginal plaintext:", plaintext)
            st.write("Key byte      :", key_padded)
            st.write("Key hex       :", key_padded.hex())
            st.write("Encrypted data:", encrypted_data.hex())
            st.write("Decrypted data:", decrypted_data.hex())
            st.write("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()