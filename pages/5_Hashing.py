import hashlib
import streamlit as st

# Define the hashing function
def hash_string(text, method='md5'):
    if method.lower() == 'md5':
        hash_object = hashlib.md5()
    elif method.lower() == 'sha1':
        hash_object = hashlib.sha1()
    elif method.lower() == 'sha256':
        hash_object = hashlib.sha256()
    elif method.lower() == 'sha512':
        hash_object = hashlib.sha512()
    else:
        raise ValueError("Invalid hashing method. Choose from md5, sha1, sha256, sha512.")
    
    hash_object.update(text.encode())
    return hash_object.hexdigest()

# Define the Streamlit app
def main():
    st.title("Hashing Function App")
    st.write("Enter a string and choose a hashing method to compute its hash.")

    # Input box for the string to hash
    input_string = st.text_input("Enter a string:")

    # Select box for the hashing method
    hash_method = st.selectbox("Select a hashing method:", ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'])

    # Compute the hash when the button is clicked
    if st.button("Hash"):
        if input_string:
            hashed_text = hash_string(input_string, method=hash_method)
            st.success(f"The {hash_method} hash of '{input_string}' is: {hashed_text}")
        else:
            st.error("Please enter a string.")

# Run the Streamlit app
if __name__ == "__main__":
    main()
