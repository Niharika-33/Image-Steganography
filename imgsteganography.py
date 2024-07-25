import cv2
import os
import hashlib
import pyotp
import qrcode
import getpass
from PIL import Image
import numpy as np

# Load the image
def load_image(image_path=None):
    if image_path is None:
        image_path = input("Enter the path to the image file: ")
    img = cv2.imread(image_path)
    if img is None:
        print("Image not found. Check the file path and make sure the image exists.")
        exit(1)
    return img, image_path

# Hash the password
def hash_password(password):
    hash_object = hashlib.sha256(password.encode())
    return hash_object.digest()

# Convert message to binary
def to_binary(data):
    if isinstance(data, str):
        return ''.join([format(ord(char), '08b') for char in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(byte, '08b') for byte in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, '08b')
    else:
        raise TypeError("Input type not supported")
  

# Embed the message in the image using LSB
def embed_message(img, message):
    # Append a delimiter to the secret message to indicate the end of the message
    message += "#####"
    binary_message = to_binary(message)
    data_index = 0
    data_len = len(binary_message)
    
    for values in img:
        for pixel in values:
            for n in range(3):  # Iterate through R, G, B channels
                if data_index < data_len:
                    pixel[n] = int(to_binary(pixel[n])[:-1] + binary_message[data_index], 2)
                    data_index += 1
                if data_index >= data_len:
                    break
            if data_index >= data_len:
                break
        if data_index >= data_len:
            break
    return img

# Save the encoded image
def save_image(img):
    encoded_image_path = "encoded_image.png"
    cv2.imwrite(encoded_image_path, img)
    print(f"Message encoded in image and saved as {encoded_image_path}")

 

# Setup TOTP for 2FA
def setup_totp(email):
    totp = pyotp.TOTP(pyotp.random_base32())
    uri = totp.provisioning_uri(name=email, issuer_name="ImgStego")
    qr = qrcode.make(uri)
    qr.save("totp_qr.png")
    print("Scan the QR code from 'totp_qr.png' with your TOTP app (e.g., Google Authenticator).")
    return totp

# Display the QR code
def display_qr_code():
    try:
        img = Image.open("totp_qr.png")
        img.show()
    except FileNotFoundError:
        print("QR code file not found.")
        exit(1)

def validate_totp(totp):
    for attempt in range(3):  # Allow up to 3 attempts
        code = input("Enter the 2FA code from your TOTP app: ")
        if totp.verify(code):
            print("2FA code verified successfully.")
            return True
        elif attempt < 2:  # If not the third attempt
            print("Invalid 2FA code. Please try again.")
    
    # After three attempts, show the final message
    print("Too many failed attempts.")
    return False

# Compute checksum of image data
def compute_image_checksum(img):
    img_bytes = img.tobytes()
    return hashlib.sha256(img_bytes).hexdigest()

# Check message integrity
def check_message_integrity(img, original_checksum):
    # Compute the checksum of the current image
    current_checksum = compute_image_checksum(img)
    return original_checksum == current_checksum

# Decode the message from the image using LSB
def decode_message(img):
    binary_data = ""
    
    for values in img:
        for pixel in values:
            for n in range(3):  # Iterate through R, G, B channels
                binary_data += to_binary(pixel[n])[-1]
    
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_message = ""
    
    for byte in all_bytes:
        decoded_message += chr(int(byte, 2))
        if decoded_message[-5:] == "#####":
            break
    
    return decoded_message[:-5]

# Main function
def main():
    print("Starting encoding process...")
    img, image_path = load_image()
    secret_message = input("Enter the secret message: ")
    password = getpass.getpass("Enter a password: ")
    hashed_password = hash_password(password)

    # Embed the message in the image
    encoded_img = embed_message(img, secret_message)
    
    # Save the encoded image and highlight overlay
    save_image(encoded_img)
    
    # Load the encoded image for decoding
    decode_img, _ = load_image("encoded_image.png")
    
    if decode_img is None:
        print("Failed to load the encoded image for decoding.")
        exit(1)
    
    # Prompt to start decoding
    input("Press Enter to start decoding...")
    
    # Check message integrity
    print("Checking message integrity...")
    if check_message_integrity(decode_img, compute_image_checksum(encoded_img)):
        print("Message integrity check passed. Proceeding with TOTP setup.")
        
        # Setup TOTP for 2FA
        email = input("Enter your email for TOTP setup: ")
        totp = setup_totp(email)
        display_qr_code()
        
        # Validate the TOTP code
        if validate_totp(totp):
            print("Authentication validated successfully. Proceeding to password verification.")
            
            # Prompt for password
            password = getpass.getpass("Enter the password to view the decoded message: ")
            if hash_password(password) == hashed_password:
                decoded_message = decode_message(decode_img)
                print(f"Decoded message: {decoded_message}")
            else:
                print("Incorrect password entered.")
                exit(1)
        else:
            print("Authentication failed. Cannot display the message.")
            exit(1)
    else:
        print("Message integrity check failed. The message may have been tampered with.")
        exit(1)

if __name__ == "__main__":
    main()
