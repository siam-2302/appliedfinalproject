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
        
        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift_key if not ifdecrypt else ord(char) - shift_key
                
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

st.title("Caesar Cipher Encryption and Decryption")

text_input = st.text_input("Enter the text:")
shift_keys_input = st.text_input("Enter the shift keys separated by space:")
submit_button = st.button("Submit")

if submit_button:
    try:
        shift_keys = [int(key) for key in shift_keys_input.split()]

        encrypted_text, enc_transformations = encrypt_decrypt(text_input, shift_keys, False)
        decrypted_text, dec_transformations = encrypt_decrypt(encrypted_text, shift_keys, True)
        
        st.write("**Transformation Details**")
        st.write("Character | Shift Key | Transformed Character")
        for i, (char, shift_key, transformed_char) in enumerate(enc_transformations):
            st.write(f"{i} {char} {shift_key} {transformed_char}")
        st.write("----------")
        for i, (char, shift_key, transformed_char) in enumerate(dec_transformations):
            st.write(f"{i} {char} {shift_key} {transformed_char}")
        
        st.write("Text:", text_input)
        st.write("Shift keys:", " ".join(str(key) for key in shift_keys))
        st.write("Cipher:", encrypted_text)
        st.write("Decrypted text:", decrypted_text)
    except ValueError as e:
        st.error(str(e))
