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
import pydicom

# Initialize GUI 
root = Tk()
root.geometry("300x200")

# Global key variables
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


def calculate_entropy(image):
    hist = Counter(image.flatten())
    total = sum(hist.values())
    entropy = -sum((count / total) * math.log2(count / total) for count in hist.values())
    return entropy


def calculate_uaci(img1, img2):
    diff = np.abs(img1.astype(np.int16) - img2.astype(np.int16))
    return np.mean(diff) / 255 * 100


def calculate_npcr(img1, img2):
    return np.sum(img1 != img2) / img1.size * 100


def plot_histogram(image, title):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
    plt.figure()
    plt.plot(hist, color='black')
    plt.title(title)
    plt.xlabel('Pixel Intensity')
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.show()


def analyze_images(img1, img2, description):
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
    print(f"Entropy: {entropy1:.4f}")
    print(f"SSIM: {ssim_index:.4f}")
    print(f"Correlation: {corr:.4f}")
    print(f"UACI: {uaci:.2f}%")
    print(f"NPCR: {npcr:.2f}%")
    print("-----------------------------\n")


def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def read_image(file_path):
    if file_path.lower().endswith(".dcm"):
        dicom_data = pydicom.dcmread(file_path)
        img_array = dicom_data.pixel_array
        if len(img_array.shape) == 2:
            img_array = cv2.cvtColor(img_array.astype(np.uint8), cv2.COLOR_GRAY2BGR)
        return img_array
    else:
        return cv2.imread(file_path)


def encrypt_image():
    generate_keys()
    file_path = filedialog.askopenfilename(filetypes=[('Image files', '*.jpg *.png *.bmp *.dcm')])
    if file_path:
        aes_key = derive_aes_key()
        print("Derived AES Key:", aes_key.hex())
        seed = int.from_bytes(aes_key[:4], 'big')

        image = read_image(file_path)
        plot_histogram(image, "Input Image Histogram")

        scrambled_image = scramble_image(image, seed)
        scrambled_path = file_path.rsplit('.', 1)[0] + "_scrambled.png"
        cv2.imwrite(scrambled_path, scrambled_image)
        print("Scrambled image saved:", scrambled_path)
        plot_histogram(scrambled_image, "Scrambled Image Histogram")

        analyze_images(image, scrambled_image, "Input vs Scrambled")

        plaintext = scrambled_image.tobytes()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        enc_file_path = file_path + ".enc"
        shape = np.array(scrambled_image.shape, dtype=np.uint16).tobytes()
        with open(enc_file_path, "wb") as f:
            f.write(shape + iv + encryptor.tag + ciphertext)

        print("SHA-256 Hash of Encrypted Data:", hash_data(ciphertext))

        encrypted_image = np.frombuffer(ciphertext[:scrambled_image.size], dtype=np.uint8)
        encrypted_image = encrypted_image.reshape(scrambled_image.shape)
        plot_histogram(encrypted_image, "Encrypted Image Histogram")

        analyze_images(scrambled_image, encrypted_image, "Scrambled vs Encrypted")

        save_keys()
        print("Encryption completed:", enc_file_path)
        print("Encryption Key (AES):", aes_key.hex())


def decrypt_image():
    load_keys()
    file_path = filedialog.askopenfilename(filetypes=[('Encrypted files', '*.enc')])
    if file_path:
        aes_key = derive_aes_key()
        print("Decryption Key (AES):", aes_key.hex())
        seed = int.from_bytes(aes_key[:4], 'big')

        with open(file_path, "rb") as f:
            data = f.read()

        shape = tuple(np.frombuffer(data[:6], dtype=np.uint16))
        iv = data[6:18]
        tag = data[18:34]
        ciphertext = data[34:]

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        decrypted_image = np.frombuffer(decrypted, dtype=np.uint8).reshape(shape)
        unscrambled_image = unscramble_image(decrypted_image, seed)
        output_path = file_path.replace(".enc", "_decrypted.png")
        cv2.imwrite(output_path, unscrambled_image)
        plot_histogram(unscrambled_image, "Decrypted Image Histogram")

        analyze_images(decrypted_image, unscrambled_image, "Encrypted vs Decrypted")

        scrambled_path = file_path.replace(".enc", "_scrambled.png")
        if os.path.exists(scrambled_path):
            scrambled_image = cv2.imread(scrambled_path)
            analyze_images(scrambled_image, unscrambled_image, "Scrambled vs Output")

        orig_path = file_path.replace(".enc", "")
        if os.path.exists(orig_path):
            original = read_image(orig_path)
            analyze_images(original, unscrambled_image, "Input vs Output")

        print("Decryption completed:", output_path)


# GUI Buttons
b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)

b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)

root.mainloop()
