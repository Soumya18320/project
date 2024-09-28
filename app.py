import streamlit as st
import base64
from datetime import datetime
import pywhatkit

def whatsapp(number, message):
    pywhatkit.sendwhatmsg_instantly(number, message)

def decrypt(message, password):
    if password == "12345":
        decode_message = message.encode("ascii")
        base64_bytes = base64.b64decode(decode_message)
        return base64_bytes.decode("ascii")
    else:
        return "Invalid Password"

def encrypt(message, password):
    if password == "12345":
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        return base64_bytes.decode("ascii")
    else:
        return "Invalid Password"

st.title("Encryption and Decryption App")

text = st.text_area("Enter text for encryption or decryption")
password = st.text_input("Enter secret key for encryption or decryption", type="password")

if st.button("ENCRYPT"):
    encrypted_message = encrypt(text, password)
    st.text_area("Encrypted Message", value=encrypted_message, height=200)

if st.button("DECRYPT"):
    decrypted_message = decrypt(text, password)
    st.text_area("Decrypted Message", value=decrypted_message, height=200)

if st.button("SEND WHATSAPP MESSAGE"):
    number = st.text_input("Enter Whatsapp number (with country code)")
    if number and encrypted_message:
        whatsapp(number, encrypted_message)
        st.success("Message sent!")
