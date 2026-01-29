from tkinter import *
from tkinter import filedialog

root = Tk()
root.geometry("200x160")

def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('JPG files', '*.jpg')])
    if file_path:
        print("Selected file:", file_path)
        key = entry1.get("1.0", "end-1c") 
        if not key.isdigit():  
            print("Invalid key. Please enter a number.")
            return
        
        key = int(key)
        with open(file_path, 'rb') as fi:
            image = bytearray(fi.read())

        for index, value in enumerate(image):
            image[index] = value ^ key  

        with open(file_path, 'wb') as fi1:
            fi1.write(image)

        print("Encryption/Decryption complete.")


b1 = Button(root, text="Encrypt/Decrypt", command=encrypt_image)
b1.place(x=50, y=10)

entry1 = Text(root, height=1, width=10)
entry1.place(x=50, y=50)

root.mainloop()