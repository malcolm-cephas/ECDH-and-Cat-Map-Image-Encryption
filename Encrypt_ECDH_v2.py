from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Initialize GUI
root = Tk()
root.geometry("300x200")

# Generate ECDH key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Simulated receiver key pair
receiver_private_key = ec.generate_private_key(ec.SECP256R1())
receiver_public_key = receiver_private_key.public_key()

# Serialize receiver's public key
receiver_public_bytes = receiver_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save public key to file
with open("receiver_public.pem", "wb") as f:
    f.write(receiver_public_bytes)

def derive_aes_key():
    """ Derives a secure AES key using ECDH and PBKDF2 """
    with open("receiver_public.pem", "rb") as f:
        peer_public_key = serialization.load_pem_public_key(f.read())
    
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use PBKDF2 to strengthen the key
    salt = b"secure_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(shared_secret)
    
    print("\n🔑 Derived AES Key (SHA-256 Hash):", key.hex())  # Display in IPython console
    return key

def encrypt_image():
    """ Encrypts image using AES-GCM """
    file_path = filedialog.askopenfilename(filetypes=[('JPG files', '*.jpg')])
    if file_path:
        aes_key = derive_aes_key()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # AES-GCM encryption
        iv = os.urandom(12)  # Generate a random IV
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Save encrypted file
        enc_file_path = file_path + ".enc"
        with open(enc_file_path, "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)  # Store IV + tag + ciphertext
        
        print("✅ Encryption complete: ", enc_file_path)

def decrypt_image():
    """ Decrypts image using AES-GCM """
    file_path = filedialog.askopenfilename(filetypes=[('Encrypted files', '*.jpg.enc')])
    if file_path:
        aes_key = derive_aes_key()
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        iv = data[:12]  # Extract IV
        tag = data[12:28]  # Extract authentication tag
        ciphertext = data[28:]  # Extract ciphertext
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Save decrypted file
        dec_file_path = file_path.replace(".enc", "_decrypted.jpg")
        with open(dec_file_path, "wb") as f:
            f.write(plaintext)
        
        print("✅ Decryption complete: ", dec_file_path)

# Buttons
b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)

b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)

root.mainloop()
