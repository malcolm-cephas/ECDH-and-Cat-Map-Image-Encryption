from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import numpy as np
import cv2

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
    
    salt = b"secure_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(shared_secret)
    print("🔑 Derived AES Key:", key.hex())  # Print AES key
    return key

def scramble_image(image, seed):
    """Scrambles image pixels using a given seed."""
    np.random.seed(seed)
    h, w, c = image.shape
    indices = np.arange(h * w)
    np.random.shuffle(indices)
    scrambled = np.zeros_like(image)
    flat_image = image.reshape(-1, c)
    scrambled.reshape(-1, c)[indices] = flat_image
    return scrambled

def unscramble_image(scrambled, seed):
    """Unscrambles image pixels using the same seed."""
    np.random.seed(seed)
    h, w, c = scrambled.shape
    indices = np.arange(h * w)
    np.random.shuffle(indices)
    unscrambled = np.zeros_like(scrambled)
    flat_scrambled = scrambled.reshape(-1, c)
    unscrambled.reshape(-1, c)[np.argsort(indices)] = flat_scrambled
    return unscrambled

def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('JPG files', '*.jpg')])
    if file_path:
        aes_key = derive_aes_key()
        seed = int.from_bytes(aes_key[:4], 'big')  # Use first 4 bytes of key as seed
        
        image = cv2.imread(file_path)
        scrambled_image = scramble_image(image, seed)
        
        scrambled_file_path = file_path.replace(".jpg", "_scrambled.jpg")
        cv2.imwrite(scrambled_file_path, scrambled_image)
        
        plaintext = scrambled_image.tobytes()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        enc_file_path = file_path + ".enc"
        with open(enc_file_path, "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)
        
        print("✅ Encryption complete: ", enc_file_path)
        print("✅ Scrambled image saved: ", scrambled_file_path)
        print("🔑 Encryption Key:", aes_key.hex())

def decrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('Encrypted files', '*.jpg.enc')])
    if file_path:
        aes_key = derive_aes_key()
        seed = int.from_bytes(aes_key[:4], 'big')
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        image_shape = cv2.imread(file_path.replace(".enc", "")).shape
        decrypted_image = np.frombuffer(plaintext, dtype=np.uint8).reshape(image_shape)
        
        unscrambled_image = unscramble_image(decrypted_image, seed)
        
        dec_file_path = file_path.replace(".enc", "_decrypted.jpg")
        cv2.imwrite(dec_file_path, unscrambled_image)
        
        print("✅ Decryption complete: ", dec_file_path)
        print("🔑 Decryption Key:", aes_key.hex())

b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)

b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)

root.mainloop()
