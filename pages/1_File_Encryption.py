import streamlit as st
from cryptography.fernet import Fernet

# Function to generate a key and instantiate a Fernet instance
def generate_key():
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    return key, cipher_suite

# Function to encrypt the file
def encrypt_file(file, cipher_suite):
    file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    return encrypted_data

# Function to decrypt the file
def decrypt_file(encrypted_data, cipher_suite):
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data

# Define the Streamlit app
def main():
    st.title("File Encryption and Decryption App")

    # File upload
    uploaded_file = st.file_uploader("Choose a file to encrypt", type=["txt", "pdf", "png", "jpg", "jpeg"])

    if uploaded_file is not None:
        # Generate key and cipher_suite
        key, cipher_suite = generate_key()
        
        st.write("Key generated. Keep this key safe to decrypt the file later.")
        
        # Encrypt the file
        if st.button("Encrypt File"):
            encrypted_data = encrypt_file(uploaded_file, cipher_suite)
            st.success("File encrypted successfully!")
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_data,
                file_name="encrypted_file.enc",
                mime="application/octet-stream"
            )
            st.session_state['key'] = key
            st.session_state['encrypted_data'] = encrypted_data

    # File upload for decryption
    if 'encrypted_data' in st.session_state:
        st.write("Upload the encrypted file to decrypt it.")
        encrypted_file = st.file_uploader("Choose an encrypted file", type=["enc"])

        if encrypted_file is not None:
            if st.button("Decrypt File"):
                try:
                    encrypted_data = st.session_state['encrypted_data']
                    key = st.session_state['key']
                    cipher_suite = Fernet(key)
                    decrypted_data = decrypt_file(encrypted_file.read(), cipher_suite)
                    st.success("File decrypted successfully!")
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_data,
                        file_name="decrypted_file",
                        mime="application/octet-stream"
                    )
                except Exception as e:
                    st.error(f"An error occurred during decryption: {str(e)}")

if __name__ == "__main__":
    main()
