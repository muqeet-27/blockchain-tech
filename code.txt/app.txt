import streamlit as st
from did import create_peer_did, update_did
from zkp import generate_keypair, create_zk_proof, verify_zk_proof
from encryption import generate_rsa_keypair, encrypt_data, decrypt_data
import time
import pandas as pd

# In-memory "database" for users and logs (simulates MongoDB)
if 'users' not in st.session_state:
    st.session_state.users = {}  # {did: {'pub_key': str, 'pub_rsa': str}}
if 'logs' not in st.session_state:
    st.session_state.logs = []  # List of dicts: {'timestamp': str, 'did': str, 'action': str, 'details': str}
if 'session' not in st.session_state:
    st.session_state.session = None  # Current logged-in DID

st.title("Decentralized Identity & Login System (DID + ZKP)")

# Generate server RSA keys (simulates end-to-end; in prod, per-user)
if 'server_priv_key' not in st.session_state:
    pub, priv = generate_rsa_keypair()
    st.session_state.server_pub_key = pub
    st.session_state.server_priv_key = priv

tab1, tab2, tab3 = st.tabs(["Register (Create DID)", "Login (ZKP Auth)", "Dashboard (Logs)"])

with tab1:
    st.header("Register")
    if st.button("Generate DID and Keypair"):
        priv_key, pub_key = generate_keypair()
        rsa_pub, rsa_priv = generate_rsa_keypair()
        did = create_peer_did(pub_key)
        
        # Encrypt sensitive data before "sending" to server
        encrypted_pub = encrypt_data(st.session_state.server_pub_key, pub_key)
        encrypted_rsa_pub = encrypt_data(st.session_state.server_pub_key, rsa_pub)
        
        # Simulate server decryption and storage
        decrypted_pub = decrypt_data(st.session_state.server_priv_key, encrypted_pub)
        decrypted_rsa_pub = decrypt_data(st.session_state.server_priv_key, encrypted_rsa_pub)
        
        st.session_state.users[did] = {'pub_key': decrypted_pub, 'pub_rsa': decrypted_rsa_pub}
        st.session_state.logs.append({
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'did': did,
            'action': 'registration',
            'details': 'DID created'
        })
        
        st.success(f"DID Created: {did}")
        st.info(f"Private Key (keep secret): {priv_key}")
        st.info(f"RSA Private Key (keep secret): {rsa_priv}")
        st.warning("In a real app, private keys are stored client-side only (e.g., wallet).")

with tab2:
    st.header("Login")
    did_input = st.text_input("Enter your DID")
    priv_key_input = st.text_input("Enter your Private Key", type="password")
    
    if st.button("Login with ZKP"):
        if did_input in st.session_state.users:
            pub_key = st.session_state.users[did_input]['pub_key']
            
            # Generate challenge (nonce)
            challenge = str(time.time())
            
            # Create ZKP (client-side)
            commitment, response = create_zk_proof(priv_key_input, challenge)
            
            # Encrypt proof before sending
            encrypted_commitment = encrypt_data(st.session_state.server_pub_key, commitment)
            encrypted_response = encrypt_data(st.session_state.server_pub_key, response)
            
            # Simulate server decryption and verification
            decrypted_commitment = decrypt_data(st.session_state.server_priv_key, encrypted_commitment)
            decrypted_response = decrypt_data(st.session_state.server_priv_key, encrypted_response)
            
            if verify_zk_proof(pub_key, challenge, decrypted_commitment, decrypted_response):
                st.session_state.session = did_input
                st.session_state.logs.append({
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'did': did_input,
                    'action': 'login',
                    'details': 'ZKP verified'
                })
                st.success("Login Successful!")
            else:
                st.error("ZKP Verification Failed")
        else:
            st.error("DID not registered")

with tab3:
    st.header("Dashboard - Activity Logs")
    if st.session_state.session:
        df = pd.DataFrame(st.session_state.logs)
        st.dataframe(df)
    else:
        st.warning("Login required to view dashboard")