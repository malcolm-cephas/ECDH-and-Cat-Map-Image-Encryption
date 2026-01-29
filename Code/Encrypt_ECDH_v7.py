from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import numpy as np
import cv2
import hashlib
from matplotlib import pyplot as plt
from skimage.metrics import structural_similarity as ssim
from scipy.stats import pearsonr
from collections import Counter
import math

root = Tk()
root.geometry("300x200")

private_key = None
receiver_private_key = None
receiver_public_key = None

def generate_keys():
    global private_key, receiver_private_key, receiver_public_key
    private_key = ec.generate_private_key(ec.SECP256R1())
    receiver_private_key = ec.generate_private_key(ec.SECP256R1())
    receiver_public_key = receiver_private_key.public_key()

def save_keys():
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open("receiver_public.pem", "wb") as f:
        f.write(receiver_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keys():
    global private_key, receiver_public_key
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("receiver_public.pem", "rb") as f:
        receiver_public_key = serialization.load_pem_public_key(f.read())

def derive_aes_key():
    shared_secret = private_key.exchange(ec.ECDH(), receiver_public_key)
    salt = b"secure_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(shared_secret)
    print("Derived ECDH Shared Secret:", shared_secret.hex())
    print("AES Key (from shared secret):", key.hex())
    return key

def scramble_image(image, seed):
    np.random.seed(seed)
    h, w, c = image.shape
    indices = np.arange(h * w)
    np.random.shuffle(indices)
    scrambled = np.zeros_like(image)
    flat_image = image.reshape(-1, c)
    scrambled.reshape(-1, c)[indices] = flat_image
    return scrambled

def unscramble_image(scrambled, seed):
    np.random.seed(seed)
    h, w, c = scrambled.shape
    indices = np.arange(h * w)
    np.random.shuffle(indices)
    unscrambled = np.zeros_like(scrambled)
    flat_scrambled = scrambled.reshape(-1, c)
    unscrambled.reshape(-1, c)[np.argsort(indices)] = flat_scrambled
    return unscrambled

def plot_histograms(images, titles):
    plt.figure(figsize=(10, 8))
    for i, (img, title) in enumerate(zip(images, titles)):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        plt.subplot(2, 2, i + 1)
        plt.hist(gray.ravel(), bins=256, range=(0, 256), color='black')
        plt.title(title)
        plt.xlabel('Pixel Intensity')
        plt.ylabel('Frequency')
    plt.tight_layout()
    plt.show()

def encrypt_image():
    generate_keys()
    file_path = filedialog.askopenfilename(filetypes=[('Image files', '*.jpg *.png *.bmp')])
    if file_path:
        aes_key = derive_aes_key()
        seed = int.from_bytes(aes_key[:4], 'big')

        image = cv2.imread(file_path)
        scrambled = scramble_image(image, seed)
        scrambled_path = file_path.rsplit('.', 1)[0] + "_scrambled.png"
        cv2.imwrite(scrambled_path, scrambled)

        plaintext = scrambled.tobytes()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        enc_file_path = file_path + ".enc"
        with open(enc_file_path, "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)

        shape = scrambled.shape
        encrypted_image = np.frombuffer(ciphertext[:np.prod(shape)], dtype=np.uint8).reshape(shape)

        save_keys()

        plot_histograms(
            [image, scrambled, encrypted_image, encrypted_image],
            ["Input Image", "Scrambled Image", "Encrypted Image", "Encrypted Image Duplicate"]
        )

def decrypt_image():
    load_keys()
    file_path = filedialog.askopenfilename(filetypes=[('Encrypted files', '*.enc')])
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
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        original_image_path = file_path.replace(".enc", "")
        scrambled_path = original_image_path.rsplit('.', 1)[0] + "_scrambled.png"
        if not os.path.exists(scrambled_path):
            print(f"Error: Scrambled image missing at {scrambled_path}.")
            return

        image_shape = cv2.imread(scrambled_path).shape
        decrypted_image = np.frombuffer(decrypted, dtype=np.uint8).reshape(image_shape)
        unscrambled_image = unscramble_image(decrypted_image, seed)
        output_path = file_path.replace(".enc", "_decrypted.png")
        cv2.imwrite(output_path, unscrambled_image)

        plot_histograms(
            [cv2.imread(original_image_path), cv2.imread(scrambled_path), decrypted_image, unscrambled_image],
            ["Input Image", "Scrambled Image", "Encrypted Image", "Decrypted Image"]
        )

b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)

b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)

root.mainloop()
