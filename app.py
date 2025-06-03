import streamlit as st
import pandas as pd  # Impor pandas untuk fungsi login
import random
import string
import base64
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import io
from streamlit_option_menu import option_menu

# --- Fungsi Enkripsi dan Dekripsi AES ---
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    # Tambahkan padding
    padded_data = pad(data, AES.block_size)
    ct_bytes = cipher.encrypt(padded_data)
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(data, key):
    iv = base64.b64decode(data[:24])
    ct = base64.b64decode(data[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

# --- Fungsi untuk Menghasilkan Kunci Alfanumerik ---
def generate_key(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# --- Fungsi Login ---
def login(user, password):
    df = pd.read_excel("credentials.xlsx", header=None)
    users = df.iloc[1:, 0].tolist()
    passwords = df.iloc[1:, 1].tolist()
    if user in users and passwords[users.index(user)] == password:
        return True
    return False

# --- UI Utama ---
st.set_page_config(page_title="🔐 File Encryption Web App", page_icon="🔒", layout="wide")

# Sidebar menu menggunakan streamlit_option_menu
with st.sidebar:
    # Memusatkan logo dan judul
    st.markdown("""
        <div style='text-align: center;'>
            <h1>Aplikasi Enkripsi File</h1>
            <img src='https://wesempire.co.ke/wp-content/uploads/2023/10/Website-Security-Protecting-Your-Business-and-User-Data.gif' width='150'>
            <h5 style='color: gray;'>Lindungi data Anda dengan enkripsi yang kuat</h5>
        </div>
    """, unsafe_allow_html=True)

    selected = option_menu("Menu", ["Login", "Home", "Fitur Utama", "Tentang"],
                           icons=['person', 'house', 'lock', 'info-circle'],
                           menu_icon="cast", default_index=0)

# Konten berdasarkan menu yang dipilih
if selected == "Login":
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    
    if st.button("Login"):
        if login(username, password):
            st.success("Login berhasil!")
            st.session_state.logged_in = True
        else:
            st.error("Username atau password salah.")

elif selected == "Home":
    if not st.session_state.get('logged_in', False):
        st.warning("Silakan login terlebih dahulu.")
    else:
        st.title("🔐 Enkripsi File bY lITBANG IHBS")
        st.markdown("<h5 style='text-align: center; color: gray;'>Lindungi data Anda dengan enkripsi yang kuat</h5>", unsafe_allow_html=True)

elif selected == "Fitur Utama":
    if not st.session_state.get('logged_in', False):
        st.warning("Silakan login terlebih dahulu.")
    else:
        st.title("Fitur Utama")
        st.markdown("""
        - **Enkripsi dan Dekripsi File**: Pilih algoritma (AES atau DES) untuk mengenkripsi atau mendekripsi file Anda.
        - **Pengelolaan Kunci**: Masukkan kunci Anda sendiri atau gunakan kunci yang dihasilkan secara acak.
        """)

elif selected == "Tentang":
    if not st.session_state.get('logged_in', False):
        st.warning("Silakan login terlebih dahulu.")
    else:
        st.title("Tentang Aplikasi")
        st.markdown("""
        Aplikasi ini dirancang untuk membantu pengguna mengenkripsi dan mendekripsi file dengan aman. 
        Dengan menggunakan algoritma enkripsi yang kuat seperti AES dan DES, 
        Anda dapat melindungi data sensitif Anda dari akses yang tidak sah.
        """)

# Input untuk enkripsi dan dekripsi
if st.session_state.get('logged_in', False):
    st.header("Proses Enkripsi dan Dekripsi")
    algorithm = st.selectbox("Pilih algoritma enkripsi:", ["AES", "DES"])
    choice = st.selectbox("Pilih aksi:", ["Encrypt File", "Decrypt File"])
    uploaded_file = st.file_uploader("Upload file untuk diproses", type=None)
    key_input = st.text_input("Masukkan kunci (16 karakter untuk AES, 8 karakter untuk DES)", max_chars=16)

    if st.button("Generate Key"):
        if algorithm == "AES":
            generated_key = generate_key(16)
        elif algorithm == "DES":
            generated_key = generate_key(8)
        st.success(f"Kunci yang dihasilkan: {generated_key}")
        key_input = generated_key

    if uploaded_file and (len(key_input) == 16 if algorithm == "AES" else len(key_input) == 8):
        key = key_input.encode()
        data = uploaded_file.read()

        if choice == "Encrypt File":
            if st.button("Encrypt"):
                if algorithm == "AES":
                    encrypted_data = aes_encrypt(data, key)
                elif algorithm == "DES":
                    # Implementasikan enkripsi DES jika diperlukan
                    pass  # Ganti dengan fungsi enkripsi DES yang sesuai

                # Simpan file terenkripsi dalam memori
                encrypted_buffer = io.BytesIO(encrypted_data.encode())

                st.success("✅ File berhasil dienkripsi.")
                st.download_button("⬇️ Download Encrypted File", encrypted_buffer, file_name=f"encrypted_{uploaded_file.name}.enc")

        elif choice == "Decrypt File":
            if st.button("Decrypt"):
                try:
                    if algorithm == "AES":
                        decrypted_data = aes_decrypt(data.decode('utf-8'), key)
                    elif algorithm == "DES":
                        # Implementasikan dekripsi DES jika diperlukan
                        pass  # Ganti dengan fungsi dekripsi DES yang sesuai

                    # Simpan file terdekripsi dalam memori
                    decrypted_buffer = io.BytesIO(decrypted_data)

                    st.success("✅ File berhasil didekripsi.")
                    st.download_button("⬇️ Download Decrypted File", decrypted_buffer, file_name=uploaded_file.name.replace(".enc", ""))
                except Exception as e:
                    st.error(f"❌ Gagal dekripsi: {e}")
    else:
        st.info("📝 Silakan upload file dan masukkan kunci yang sesuai.")

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>© 2025 File Encryption By Litbang. All rights reserved.</p>", unsafe_allow_html=True)
