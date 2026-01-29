from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import numpy as np
import cv2
import hashlib
from matplotlib import pyplot as plt
from skimage.metrics import structural_similarity as ssim
from scipy.stats import pearsonr
from collections import Counter
import math
import pydicom
import struct


#GUI Initialisation
root = Tk()
root.geometry("300x200")

# Keys
receiver_private_key = None
receiver_public_key = None

#Key Genreation and Storage
def generate_receiver_keys():
    global receiver_private_key, receiver_public_key
    receiver_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    receiver_public_key = receiver_private_key.public_key()

def save_receiver_keys():
    if receiver_private_key is None or receiver_public_key is None:
        print("No receiver keys to save.")
        return
    
    #saving private key
    with open("receiver_private.pem", "wb") as f:
        f.write(receiver_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        #Saving public key
    with open("receiver_public.pem", "wb") as f:
        f.write(receiver_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Receiver keys saved: receiver_private.pem, receiver_public.pem")

def load_receiver_private():
    global receiver_private_key, receiver_public_key
    try:
        with open("receiver_private.pem", "rb") as f:
            receiver_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        receiver_public_key = receiver_private_key.public_key()
        print("Loaded receiver_private.pem")
    except Exception as e:
        print("Failed to load receiver_private.pem:", e)

#key derivation using hmac based key derivation function
def derive_aes_key_from_shared(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'ecdh-image-encryption',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

#image scrambling
def scramble_image(image: np.ndarray, seed: int) -> np.ndarray:
    h, w, c = image.shape
    rng = np.random.default_rng(seed)
    indices = np.arange(h * w)
    rng.shuffle(indices)
    flat = image.reshape(-1, c)
    scrambled_flat = np.zeros_like(flat)
    scrambled_flat[indices] = flat
    scrambled = scrambled_flat.reshape(h, w, c)
    return scrambled

#image unscrambing
def unscramble_image(scrambled: np.ndarray, seed: int) -> np.ndarray:
    h, w, c = scrambled.shape
    rng = np.random.default_rng(seed)
    indices = np.arange(h * w)
    rng.shuffle(indices)
    flat = scrambled.reshape(-1, c)
    unscrambled_flat = np.zeros_like(flat)
    unscrambled_flat[np.argsort(indices)] = flat
    unscrambled = unscrambled_flat.reshape(h, w, c)
    return unscrambled

#image quality metric cross check
def calculate_entropy(image: np.ndarray) -> float:
    hist = Counter(image.flatten())
    total = sum(hist.values())
    entropy = -sum((count / total) * math.log2(count / total) for count in hist.values() if count > 0)
    return entropy

def calculate_uaci(img1: np.ndarray, img2: np.ndarray) -> float:
    diff = np.abs(img1.astype(np.int16) - img2.astype(np.int16))
    return np.mean(diff) / 255 * 100

def calculate_npcr(img1: np.ndarray, img2: np.ndarray) -> float:
    return np.sum(img1 != img2) / img1.size * 100

def plot_histogram_bytes(data: bytes, title: str):
    arr = np.frombuffer(data, dtype=np.uint8)
    hist, _ = np.histogram(arr, bins=256, range=(0,255))
    plt.figure()
    plt.plot(hist)
    plt.title(title)
    plt.xlabel('Byte value')
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.show()

def analyze_images(img1: np.ndarray, img2: np.ndarray, description: str):
    gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
    if gray1.shape != gray2.shape:
        gray2 = cv2.resize(gray2, (gray1.shape[1], gray1.shape[0]))
    entropy1 = calculate_entropy(gray1)
    entropy2 = calculate_entropy(gray2)
    ssim_index = ssim(gray1, gray2)
    corr, _ = pearsonr(gray1.flatten(), gray2.flatten())
    uaci = calculate_uaci(gray1, gray2)
    npcr = calculate_npcr(gray1, gray2)
    print(f"\n--- {description} ---")
    print(f"Entropy (img1): {entropy1:.4f}")
    print(f"Entropy (img2): {entropy2:.4f}")
    print(f"SSIM: {ssim_index:.4f}")
    print(f"Correlation: {corr:.4f}")
    print(f"UACI: {uaci:.2f}%")
    print(f"NPCR: {npcr:.2f}%")
    print("-----------------------------\n")

#compute hash 256 fro integrtiry verification
def hash_data(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

#reading function fro the image
def read_image(file_path: str) -> np.ndarray:
    if file_path.lower().endswith(".dcm"):
        dicom_data = pydicom.dcmread(file_path)
        img_array = dicom_data.pixel_array
        if len(img_array.shape) == 2:
            img_array = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_GRAY2BGR)
        return img_array
    else:
        img = cv2.imread(file_path)
        return img

def encrypt_image():
    # Ensure receiver keys exist (the receiver_private.pem should be separate in real deployments)
    if receiver_private_key is None:
        generate_receiver_keys()
        save_receiver_keys()
    file_path = filedialog.askopenfilename(filetypes=[('Image files', '*.jpg *.png *.bmp *.dcm')])
    if not file_path:
        return
    # Sender generates ephemeral key pair
    sender_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sender_public = sender_private.public_key()
    sender_pub_bytes = sender_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    image = read_image(file_path)
    if image is None:
        messagebox.showerror("Error", "Failed to read image.")
        return
    # derive shared secret and AES key: sender_private.exchange with receiver_public_key
    shared = sender_private.exchange(ec.ECDH(), receiver_public_key)
    salt = os.urandom(16)
    aes_key = derive_aes_key_from_shared(shared, salt)
    print("Derived AES key (hex):", aes_key.hex())
    # scramble using a seed derived from key + salt (so deterministic for same key)
    seed = int.from_bytes(hashlib.sha256(aes_key + salt).digest()[:4], 'big')
    plot_histogram_bytes(image.tobytes()[:min(65536, image.size)], "Input (sample bytes) Histogram")
    scrambled = scramble_image(image, seed)
    scrambled_path = file_path.rsplit('.', 1)[0] + "_scrambled.png"
    cv2.imwrite(scrambled_path, scrambled)
    print("Scrambled image saved:", scrambled_path)
    analyze_images(image, scrambled, "Input vs Scrambled")
    plaintext = scrambled.tobytes()
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    # File layout: shape(3*uint16)=6 bytes | salt(16) | sender_pub_len(uint16)=2 | sender_pub | iv(12) | tag(16) | ciphertext
    shape_bytes = np.array(scrambled.shape, dtype=np.uint16).tobytes()
    sender_len = struct.pack(">H", len(sender_pub_bytes))
    enc_file_path = file_path + ".enc"
    with open(enc_file_path, "wb") as f:
        f.write(shape_bytes)
        f.write(salt)
        f.write(sender_len)
        f.write(sender_pub_bytes)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)
    print("Encrypted file written:", enc_file_path)
    print("SHA-256 of ciphertext:", hash_data(ciphertext))
    # Plot a histogram of ciphertext bytes (not reshaping into image)
    plot_histogram_bytes(ciphertext[:65536], "Ciphertext (sample bytes) Histogram")
    analyze_images(scrambled, cv2.cvtColor(np.frombuffer(ciphertext[:min(ciphertext.size, scrambled.size)], dtype=np.uint8).reshape(scrambled.shape, order='C') if False else scrambled, cv2.COLOR_BGR2GRAY), "Scrambled vs Ciphertext (note: this comparison is heuristic)")
    messagebox.showinfo("Done", f"Encrypted and saved to {enc_file_path}")

def decrypt_image():
    load_receiver_private()  # attempt to load receiver private if available
    if receiver_private_key is None:
        messagebox.showerror("Missing key", "Receiver private key not loaded. Place receiver_private.pem in working folder.")
        return
    file_path = filedialog.askopenfilename(filetypes=[('Encrypted files', '*.enc')])
    if not file_path:
        return
    with open(file_path, "rb") as f:
        data = f.read()
    # parse header
    ptr = 0
    shape = tuple(np.frombuffer(data[ptr:ptr+6], dtype=np.uint16))
    ptr += 6
    salt = data[ptr:ptr+16]; ptr += 16
    sender_len = struct.unpack(">H", data[ptr:ptr+2])[0]; ptr += 2
    sender_pub_bytes = data[ptr:ptr+sender_len]; ptr += sender_len
    iv = data[ptr:ptr+12]; ptr += 12
    tag = data[ptr:ptr+16]; ptr += 16
    ciphertext = data[ptr:]
    # load sender public key from bytes
    sender_public = serialization.load_der_public_key(sender_pub_bytes, backend=default_backend())
    shared = receiver_private_key.exchange(ec.ECDH(), sender_public)
    aes_key = derive_aes_key_from_shared(shared, salt)
    print("Derived AES key (hex):", aes_key.hex())
    # decrypt
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    try:
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        messagebox.showerror("Decryption failed", f"AEAD failure or corrupted data: {e}")
        return
    decrypted_array = np.frombuffer(decrypted, dtype=np.uint8).reshape(shape)
    seed = int.from_bytes(hashlib.sha256(aes_key + salt).digest()[:4], 'big')
    unscrambled = unscramble_image(decrypted_array, seed)
    out_path = file_path.replace(".enc", "_decrypted.png")
    cv2.imwrite(out_path, unscrambled)
    plot_histogram_bytes(unscrambled.tobytes()[:65536], "Decrypted (sample bytes) Histogram")
    analyze_images(decrypted_array, unscrambled, "Encrypted vs Decrypted (unscrambled)")
    # try to compare original if exists
    orig_path = file_path.replace(".enc", "")
    if os.path.exists(orig_path):
        orig = read_image(orig_path)
        analyze_images(orig, unscrambled, "Original vs Output")
    messagebox.showinfo("Done", f"Decryption complete: {out_path}")

# GUI Buttons
b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)
b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)
root.mainloop()
