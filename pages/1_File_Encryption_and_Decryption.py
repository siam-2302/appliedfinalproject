import streamlit as st
from cryptography.fernet import Fernet

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

# Define the Streamlit app
def main():
    st.title("File Encryption and Decryption App")


    st.header("File Encryption and Decryption")

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

if __name__ == "__main__":
    main()
