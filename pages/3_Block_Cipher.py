import streamlit as st
import hashlib

st.header("Block Cipher - XOR Encryption Demo")

def pad(data, block_size):
    """ Pad data to make its length a multiple of block_size. """
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    """ Remove padding from data. """
    padding_length = data[-1]
    return data[:-padding_length]

def xor_encrypted_block(plaintext_block, key):
    """ Encrypt a block of data by XORing with a key. """
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block

def xor_decrypt(ciphertext, key, block_size):
    """ Decrypt data encrypted with XOR encryption. """
    decrypted_data = b''
    st.write("Decrypted blocks:")
    for x, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i + block_size]
        decrypted_block = xor_encrypted_block(ciphertext_block, key)
        decrypted_data += decrypted_block
        st.write(f"Block[{x}]: {decrypted_block.hex()} - {decrypted_block}")
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

def xor_encrypt(plaintext, key, block_size):
    """ Encrypt plaintext using XOR encryption. """
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    st.write("Encrypted blocks:")
    for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i + block_size]
        st.write(f"Plain block[{x}]: {plaintext_block.hex()} - {plaintext_block}")
        encrypted_block = xor_encrypted_block(plaintext_block, key)
        encrypted_data += encrypted_block
        st.write(f"Cipher block[{x}]: {encrypted_block.hex()} - {encrypted_block}")
    return encrypted_data

def main():
    plaintext = st.text_input("Enter plaintext:")
    key = st.text_input("Enter key:")
    block_size = st.number_input("Enter block size:", value=16, step=1, min_value=1)

    if st.button("Encrypt & Decrypt"):
        plaintext_bytes = bytes(plaintext, 'utf-8')
        key_bytes = bytes(key, 'utf-8')
        
        # Ensuring the key is padded correctly
        key_padded = pad(key_bytes, block_size) if len(key_bytes) % block_size != 0 else key_bytes
        
        encrypted_data = xor_encrypt(plaintext_bytes, key_padded, block_size)
        decrypted_data = xor_decrypt(encrypted_data, key_padded, block_size)
        
        st.write("Original plaintext:", plaintext)
        st.write("Key bytes:", key_padded)
        st.write("Key hex:", key_padded.hex())
        st.write("Encrypted data:", encrypted_data.hex())
        st.write("Decrypted data (hex):", decrypted_data.hex())
        st.write("Decrypted data (text):", decrypted_data.decode('utf-8'))

if __name__ == "__main__":
    main()
