import streamlit as st
import hashlib

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts or decrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt or decrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: Flag indicating whether to decrypt or encrypt.
    Returns:
        A string containing the encrypted or decrypted text.
    """
    result = ""
    transformations = []
    
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
    
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        
        char_ascii = ord(char)  # Convert char to ASCII value
        
        if 32 <= char_ascii <= 125:
            new_ascii = char_ascii + shift_key if not ifdecrypt else char_ascii - shift_key
                
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
                
            result += chr(new_ascii)
            transformations.append((char, shift_key, chr(new_ascii)))
        else:
            result += char
            transformations.append((char, "", char))
    return result, transformations

def file_encrypt_decrypt(file_content, shift_keys, ifdecrypt):
    """
    Encrypts or decrypts file content using Caesar Cipher with a list of shift keys.
    Args:
        file_content: The content of the file to encrypt or decrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: Flag indicating whether to decrypt or encrypt.
    Returns:
        A string containing the encrypted or decrypted file content.
    """
    text_content = file_content.decode("latin-1")  # Convert bytes to string
    return encrypt_decrypt(text_content, shift_keys, ifdecrypt)

st.title("Caesar Cipher File Encryption and Decryption")

file = st.file_uploader("Upload a file")

if file is not None:
    file_content = file.getvalue()  # No need for decoding
    st.text_area("File content", value=file_content.decode("latin-1"), height=300)

    text_input = st.text_input("Enter the text:")
    shift_keys_input = st.text_input("Enter the shift keys separated by space:")
    decrypt_checkbox = st.checkbox("Decrypt")

    submit_button = st.button("Submit")

    if submit_button:
        try:
            shift_keys = [int(key) for key in shift_keys_input.split()]

            if file_content:
                result, _ = file_encrypt_decrypt(file_content, shift_keys, decrypt_checkbox)
                st.text_area("Encrypted/Decrypted File Content", value=result, height=300)
                
                if decrypt_checkbox:
                    # Download decrypted file
                    st.download_button(
                        label="Download Decrypted File",
                        data=result.encode("latin-1"),
                        file_name="decrypted_file.txt",
                        mime="text/plain"
                    )
            elif text_input:
                result, _ = encrypt_decrypt(text_input, shift_keys, decrypt_checkbox)
                st.text_area("Encrypted/Decrypted Text", value=result, height=300)
        except ValueError as e:
            st.error(str(e))
