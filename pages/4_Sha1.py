import streamlit as st
import hashlib

def hash_text(text):
    space_hash = '5C1CE938EC4B836703C845A1D8DB57348758F283'
    hashed_chars = set()
    hash_text = hashlib.sha1(text.encode()).hexdigest().upper()
    output = []
    
    for char in text:
        if char == ' ':
            if space_hash not in hashed_chars:
                hashed_chars.add(space_hash)
                output.append(f"{space_hash} <space>")
                
        else:
            hashed_value = hashlib.sha1(char.encode()).hexdigest().upper()
            if hashed_value not in hashed_chars:
                hashed_chars.add(hashed_value)
                output.append(f"{hashed_value} {char}")

    output.append(f"{hash_text} {text}")
    return output
    
st.title("Sha1")

text_input = st.text_input("Enter text:")
if st.button("Submit"):
    if text_input:
        output = hash_text(text_input)
        st.write("Output:")
        for line in output:
            st.write(line)
    else:
        st.write("Please enter some text.")
