# Copyright (c) Streamlit Inc. (2018-2022) Snowflake Inc. (2022)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Hello",
        page_icon="👋",
    )

    st.write("# Welcome our Repository/Final Project! 👋")
    st.write("BY: CHRISTIAN SIAM B BUSADRE, Jerome Llaban and Mae Julienn Arbo Mata ")


    st.markdown(
        """
    Here you can select from a variety of ciphers:
    - [XOR Cipher]: It is used with a key when encrypting and decrypting a series of plaintext bytes.
    - [Caesar Cipher]: Simple encryption method wherer each letter in the plaintext is shifter a certain number  of places down the alphabet.
    - [Primitive Root]: A mathematical concept used in certain cryptographic algorithms.
    - [Block Cipher]: A symmetric key cryptographic algorithm operating on fixed-length groups of bits, called blocks.
    - [Sha1]: Converting text input to hash value
    """
    )


if __name__ == "__main__":
    run()