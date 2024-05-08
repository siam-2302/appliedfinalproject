import streamlit as st
import hashlib

st.header("Ceasar Cipher")

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    result = ""
    print_output = ""

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
            print_output += f"{i} {char} {shift_key} {result[i]}\n"
        else:
            result += char
            print_output += f"{i} {char} {shift_key} {result[i]}\n"

    return result, print_output

def main():

    text_input = st.text_input("Enter text:")
    keys_input = st.text_input("Enter shift keys separated by space:")

    if st.button("Submit"):
        shift_keys = [int(key) for key in keys_input.split()]
        encrypted_text, print_output_enc = encrypt_decrypt(text_input, shift_keys, False)
        st.write("Cipher:")
        st.write(print_output_enc)
        st.write("----------")
        st.write("Encrypted text:")
        st.write(encrypted_text)
        st.write("----------")
        decrypted_text, print_output_dec = encrypt_decrypt(encrypted_text, shift_keys, True)
        st.write("Decrypted text:")
        st.write(decrypted_text)
        st.write("----------")
        st.write("Decryption details:")
        st.write(print_output_dec)

if __name__ == "__main__":
    main()