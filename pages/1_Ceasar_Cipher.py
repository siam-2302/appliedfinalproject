import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    result = ""
    
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
    
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        
        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift_key if not ifdecrypt else ord(char) -shift_key
                
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
                
            result += chr(new_ascii)
        else:
            result += char
    return result

st.title("Caesar Cipher Encryption and Decryption")

text_input = st.text_input("Enter the text:")
shift_keys_input = st.text_input("Enter the shift keys separated by space:")

if st.button("Encrypt"):
    try:
        shift_keys = [int(key) for key in shift_keys_input.split()]
        enc = encrypt_decrypt(text_input, shift_keys, False)
        st.write("Encrypted Text:", enc)
    except ValueError as e:
        st.error(str(e))

if st.button("Decrypt"):
    try:
        shift_keys = [int(key) for key in shift_keys_input.split()]
        dec = encrypt_decrypt(text_input, shift_keys, True)
        st.write("Decrypted Text:", dec)
    except ValueError as e:
        st.error(str(e))
