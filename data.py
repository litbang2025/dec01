import streamlit as st
import os
import pandas as pd
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64
import random
import string
import datetime

# --- Fungsi Enkripsi dan Dekripsi AES ---
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct  # Mengembalikan IV dan ciphertext

def aes_decrypt(data, key):
    iv = base64.b64decode(data[:24])  # Mengambil IV dari data
    ct = base64.b64decode(data[24:])  # Mengambil ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

# --- Fungsi Enkripsi dan Dekripsi DES ---
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct  # Mengembalikan IV dan ciphertext

def des_decrypt(data, key):
    iv = base64.b64decode(data[:24])  # Mengambil IV dari data
    ct = base64.b64decode(data[24:])  # Mengambil ciphertext
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt

# --- Fungsi untuk Menghasilkan Kunci Alfanumerik ---
def generate_key(length):
    characters = string.ascii_letters + string.digits  # Kombinasi huruf dan angka
    return ''.join(random.choice(characters) for _ in range(length))

# --- Fungsi untuk Mencatat Aktivitas ke Excel ---
def record_activity(file_name, action, algorithm, key):
    # Buat DataFrame
    data = {
        "Timestamp": [datetime.datetime.now()],
        "File Name": [file_name],
        "Action": [action],
        "Algorithm": [algorithm],
        "Key": [key]
    }
    df = pd.DataFrame(data)

    # Tentukan nama file Excel
    excel_file = "activity_log.xlsx"

    # Cek apakah file sudah ada
    if os.path.exists(excel_file):
        # Jika ada, tambahkan data baru
        existing_df = pd.read_excel(excel_file)
        df = pd.concat([existing_df, df], ignore_index=True)

    # Simpan DataFrame ke Excel
    df.to_excel(excel_file, index=False)

# --- UI Utama ---
st.set_page_config(page_title="🔐 File Encryption Web App", page_icon="🔒", layout="wide")

# Sidebar menu
st.sidebar.title("Menu")
menu_options = ["Home", "Fitur Utama", "Tentang"]
choice = st.sidebar.selectbox("Pilih Halaman", menu_options)

# Konten untuk setiap menu
if choice == "Home":
    st.title("🔐 Selamat Datang di Aplikasi Enkripsi File")
    st.markdown("<h5 style='text-align: center; color: gray;'>Lindungi data Anda dengan enkripsi yang kuat</h5>", unsafe_allow_html=True)

elif choice == "Fitur Utama":
    st.title("Fitur Utama")
    st.markdown("""
    - **Enkripsi dan Dekripsi File**: Pilih algoritma (AES atau DES) untuk mengenkripsi atau mendekripsi file Anda.
    - **Pengelolaan Kunci**: Masukkan kunci Anda sendiri atau gunakan kunci yang dihasilkan secara acak.
    - **Pencatatan Aktivitas**: Semua aktivitas dicatat dalam file Excel untuk keperluan audit.
    """)

elif choice == "Tentang":
    st.title("Tentang Aplikasi")
    st.markdown("""
    Aplikasi ini dirancang untuk membantu pengguna mengenkripsi dan mendekripsi file dengan aman. 
    Dengan menggunakan algoritma enkripsi yang kuat seperti AES dan DES, 
    Anda dapat melindungi data sensitif Anda dari akses yang tidak sah.
    """)

# Input untuk enkripsi dan dekripsi
st.header("Proses Enkripsi dan Dekripsi")

# Buat folder user jika belum ada
username = "default_user"  # Anda bisa mengganti ini dengan nama pengguna default
user_base = os.path.join("user_data", username)
for subfolder in ["keys", "encrypted", "decrypted"]:
    os.makedirs(os.path.join(user_base, subfolder), exist_ok=True)
os.makedirs("uploads", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Pilihan algoritma enkripsi
algorithm = st.selectbox("Pilih algoritma enkripsi:", ["AES", "DES"])

choice = st.selectbox("Pilih aksi:", ["Encrypt File", "Decrypt File"])

uploaded_file = st.file_uploader("Upload file untuk diproses", type=None)

key_input = st.text_input("Masukkan kunci (16 karakter untuk AES, 8 karakter untuk DES)", max_chars=16)

# Tombol untuk menghasilkan kunci
if st.button("Generate Key"):
    if algorithm == "AES":
        generated_key = generate_key(16)  # 16 karakter untuk AES
    elif algorithm == "DES":
        generated_key = generate_key(8)  # 8 karakter untuk DES
    st.success(f"Kunci yang dihasilkan: {generated_key}")
    key_input = generated_key  # Mengatur input kunci ke kunci yang dihasilkan

if uploaded_file and (len(key_input) == 16 if algorithm == "AES" else len(key_input) == 8):
    key = key_input.encode()
    data = uploaded_file.read()

    if choice == "Encrypt File":
        if st.button("Encrypt"):
            if algorithm == "AES":
                encrypted_data = aes_encrypt(data, key)
            elif algorithm == "DES":
                encrypted_data = des_encrypt(data, key)

            encrypted_path = os.path.join(user_base, "encrypted", uploaded_file.name + ".enc")
            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data.encode())

            st.success(f"✅ File berhasil dienkripsi: `{encrypted_path}`")
            st.download_button("⬇️ Download Encrypted File", encrypted_data.encode(), file_name=uploaded_file.name + ".enc")

            # Mencatat aktivitas
            record_activity(uploaded_file.name, "Encrypt", algorithm, key_input)

    elif choice == "Decrypt File":
        if st.button("Decrypt"):
            try:
                if algorithm == "AES":
                    decrypted_data = aes_decrypt(data.decode('utf-8'), key)
                elif algorithm == "DES":
                    decrypted_data = des_decrypt(data.decode('utf-8'), key)

                decrypted_path = os.path.join(user_base, "decrypted", uploaded_file.name.replace(".enc", ""))
                with open(decrypted_path, "wb") as f:
                    f.write(decrypted_data)

                st.success(f"✅ File berhasil didekripsi: `{decrypted_path}`")
                st.download_button("⬇️ Download Decrypted File", decrypted_data, file_name=uploaded_file.name.replace(".enc", ""))

                # Mencatat aktivitas
                record_activity(uploaded_file.name, "Decrypt", algorithm, key_input)
            except Exception as e:
                st.error(f"❌ Gagal dekripsi: {e}")
else:
    st.info("📝 Silakan upload file dan masukkan kunci yang sesuai.")

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>© 2025 File Encryption Web App. All rights reserved.</p>", unsafe_allow_html=True)
