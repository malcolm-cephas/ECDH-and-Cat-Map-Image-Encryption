from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

root = Tk()
root.geometry("300x200")

# Generate ECDH key pair (Same key used for both encryption & decryption)
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Simulated receiver key pair (In real-world, exchange public keys)
receiver_private_key = ec.generate_private_key(ec.SECP256R1())
receiver_public_key = receiver_private_key.public_key()

# Serialize receiver's public key
receiver_public_bytes = receiver_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

def derive_shared_key():
    """ Derives a shared secret key using ECDH """
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), receiver_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Hash the shared secret to derive encryption key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    key = digest.finalize()

    print("\n🔑 Derived Shared Key (SHA-256 Hash):", key.hex())  # Display in IPython console
    return key

def encrypt_image():
    """ Encrypts the selected image using XOR with ECDH-derived key """
    file_path = filedialog.askopenfilename(filetypes=[('JPG files', '*.jpg')])
    if file_path:
        print("\nEncrypting:", file_path)
        shared_key = derive_shared_key()  # Displays key in console

        with open(file_path, 'rb') as fi:
            image = bytearray(fi.read())

        # XOR encryption
        for i in range(len(image)):
            image[i] ^= shared_key[i % len(shared_key)]

        with open(file_path, 'wb') as fi1:
            fi1.write(image)

        print("✅ Encryption complete.")

def decrypt_image():
    """ Decrypts the selected image by reapplying XOR with the same ECDH-derived key """
    file_path = filedialog.askopenfilename(filetypes=[('JPG files', '*.jpg')])
    if file_path:
        print("\nDecrypting:", file_path)
        shared_key = derive_shared_key()  # Displays key in console

        with open(file_path, 'rb') as fi:
            image = bytearray(fi.read())

        # XOR decryption (Same process as encryption)
        for i in range(len(image)):
            image[i] ^= shared_key[i % len(shared_key)]

        with open(file_path, 'wb') as fi1:
            fi1.write(image)

        print("✅ Decryption complete.")

# Buttons for Encrypt and Decrypt
b1 = Button(root, text="Encrypt Image", command=encrypt_image)
b1.place(x=90, y=50)

b2 = Button(root, text="Decrypt Image", command=decrypt_image)
b2.place(x=90, y=100)

root.mainloop()
