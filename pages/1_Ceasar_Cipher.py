import streamlit as st

def encrypt_decrypt(text, shift_keys):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
    Returns:
        A string containing the encrypted text.
    """
    result = ""
    
    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")
    
    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]
        
        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift_key
                
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
                
            result += chr(new_ascii)
        else:
            result += char
    return result

def main():
    st.title("Caesar Cipher Encryption")
    
    text = st.text_input("Enter text:")
    shift_keys_input = st.text_input("Enter shift keys (separated by space):")

    if st.button("Submit"):
        try:
            shift_keys = [int(key) for key in shift_keys_input.split()]
            result = encrypt_decrypt(text, shift_keys)
            st.write("Result:", result)
        except Exception as e:
            st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
