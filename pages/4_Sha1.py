import streamlit as st
import hashlib

def hash_text(text):
    space_hash = '5C1CE938EC4B836703C845A1D8DB57348758F283'
    hashed_chars = set()
    hash_text = hashlib.sha1(text.encode()).hexdigest().upper()
    
    result = ""
    for char in text:
        if char == ' ':
            if space_hash not in hashed_chars:
                hashed_chars.add(space_hash)
                result += f"{space_hash} <space>\n"
                
        else:
            hashed_value = hashlib.sha1(char.encode()).hexdigest().upper()
            if hashed_value not in hashed_chars:
                hashed_chars.add(hashed_value)
                result += f"{hashed_value} {char}\n"
    
    result += f"\nSHA1 Hash: {hash_text}\nInput Text: {text}"
    return result

st.title("Text Hashing App")

input_text = st.text_input("Enter text:")
submitted = st.button("Submit")

if submitted:
    if input_text:
        result = hash_text(input_text)
        st.text_area("Hashed Text", value=result, height=300)
    else:
        st.warning("Please enter some text.")
