from tkinter import Tk, filedialog
import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim
from scipy.stats import pearsonr

def calculate_uiqi(img1, img2):
    """Calculates UIQI (Universal Image Quality Index)"""
    img1 = img1.astype(np.float64)
    img2 = img2.astype(np.float64)
    
    mean1 = np.mean(img1)
    mean2 = np.mean(img2)
    var1 = np.var(img1)
    var2 = np.var(img2)
    covar = np.mean((img1 - mean1) * (img2 - mean2))
    
    numerator = 4 * mean1 * mean2 * covar
    denominator = (mean1**2 + mean2**2) * (var1 + var2)
    if denominator == 0:
        return 0
    return numerator / denominator

def select_and_compare_images():
    # Hide main window
    root = Tk()
    root.withdraw()

    # Ask for two images
    file_path1 = filedialog.askopenfilename(title="Select the first image", filetypes=[("Image files", "*.jpg *.png *.bmp")])
    file_path2 = filedialog.askopenfilename(title="Select the second image", filetypes=[("Image files", "*.jpg *.png *.bmp")])

    if file_path1 and file_path2:
        # Read and convert to grayscale
        img1 = cv2.imread(file_path1, cv2.IMREAD_GRAYSCALE)
        img2 = cv2.imread(file_path2, cv2.IMREAD_GRAYSCALE)

        # Resize if dimensions mismatch
        if img1.shape != img2.shape:
            print("Resizing second image to match the first image...")
            img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

        # SSIM between the images
        ssim_index, _ = ssim(img1, img2, full=True)

        # UIQI between the images
        uiqi_index = calculate_uiqi(img1, img2)

        # Correlation
        img1_flat = img1.flatten()
        img2_flat = img2.flatten()
        corr, _ = pearsonr(img1_flat, img2_flat)

        # Calculate SSIM and UIQI of each image with itself (always 1.0)
        ssim_img1, _ = ssim(img1, img1, full=True)
        ssim_img2, _ = ssim(img2, img2, full=True)
        uiqi_img1 = calculate_uiqi(img1, img1)
        uiqi_img2 = calculate_uiqi(img2, img2)

        # Print results
        print("\n--- Image Comparison Results ---")
        print(f"Selected Image 1: {file_path1}")
        print(f"Selected Image 2: {file_path2}\n")
        #print(f"SSIM of Image 1 = {ssim_img1:.4f}")
        #print(f"SSIM of Image 2 = {ssim_img2:.4f}")
        #print(f"UIQI of Image 1 = {uiqi_img1:.4f}")
        #print(f"UIQI of Image 2 = {uiqi_img2:.4f}")
        print(f"\nSSIM between the two images = {ssim_index:.4f}")
        print(f"UACI between the two images = {uiqi_index:.4f}")
        print(f"Pearson Correlation Coefficient = {corr:.4f}")
        print("--------------------------------\n")

    else:
        print("No image selected!")

if __name__ == "__main__":
    select_and_compare_images()
