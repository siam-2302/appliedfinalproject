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
    st.title("Symmetric Encryption and Decryption App")

    # Sidebar for key management
    st.sidebar.header("Key Management")
    if "key" not in st.session_state:
        st.session_state.key = None

    if st.session_state.key is None:
        if st.sidebar.button("Generate Key"):
            key, cipher_suite = generate_key()
            st.session_state.key = key
            st.session_state.cipher_suite = cipher_suite
            st.sidebar.success("Key generated successfully!")
            st.sidebar.write(f"Key: {key.decode()}")
    else:
        st.sidebar.write(f"Key: {st.session_state.key.decode()}")
        st.session_state.cipher_suite = Fernet(st.session_state.key)
        if st.sidebar.button("Delete Key"):
            st.session_state.key = None
            st.sidebar.success("Key deleted successfully!")

    st.header("Text Encryption and Decryption")

    text_input = st.text_area("Enter text to encrypt/decrypt:")

    if text_input:
        if st.button("Encrypt Text"):
            encrypted_text = encrypt_text(text_input, st.session_state.cipher_suite)
            st.success("Text encrypted successfully!")
            st.text_area("Encrypted Text", encrypted_text.decode())

        encrypted_text_input = st.text_area("Enter text to decrypt:")

        if st.button("Decrypt Text"):
            try:
                decrypted_text = decrypt_text(encrypted_text_input.encode(), st.session_state.cipher_suite)
                st.success("Text decrypted successfully!")
                st.text_area("Decrypted Text", decrypted_text)
            except Exception as e:
                st.error(f"An error occurred during decryption: {str(e)}")

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
