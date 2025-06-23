from PIL import Image

# --- Utility Functions ---
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

# --- Steganography Functions ---
def encode_image(image_path, secret_message, key, output_image_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = list(img.getdata())

    # Add delimiter '~' to mark end of message
    encrypted = xor_encrypt_decrypt(secret_message + '~', key)
    binary_data = text_to_bin(encrypted)

    if len(binary_data) > len(pixels) * 3:
        print("❌ Message too long for this image.")
        return False

    new_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel
        if data_index < len(binary_data):
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_image_path)
    print(f"[✔] Encrypted image saved as '{output_image_path}'")
    return True

def decode_image(image_path, key):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = list(img.getdata())

    binary_data = ''
    for pixel in pixels:
        for channel in pixel:
            binary_data += str(channel & 1)

    # Split binary into bytes and convert to chars
    binary_chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    extracted = ''
    for byte in binary_chars:
        if len(byte) < 8:
            continue
        char = chr(int(byte, 2))
        extracted += char
        if extracted.endswith('~'):  # end marker
            break

    # Remove delimiter and decrypt
    if not extracted.endswith('~'):
        print("❌ No hidden message found.")
        return None

    extracted = extracted[:-1]
    decrypted = xor_encrypt_decrypt(extracted, key)
    return decrypted

# --- Main Program ---
def main():
    mode = input("Choose operation (encrypt/decrypt): ").strip().lower()

    if mode == "encrypt":
        image_path = input("Enter input PNG image path: ").strip()
        secret_message = input("Enter secret message to hide: ")
        key = input("Enter encryption key: ")

        output_image = input("Enter output image filename (with .png): ").strip()
        if not output_image.lower().endswith('.png'):
            output_image += '.png'

        success = encode_image(image_path, secret_message, key, output_image)
        if not success:
            print("Encryption failed.")

    elif mode == "decrypt":
        image_path = input("Enter PNG image path to decode: ").strip()
        key = input("Enter decryption key: ")

        message = decode_image(image_path, key)
        if message is not None:
            print(f"[✔] Decrypted message: {message}")
        else:
            print("Failed to decrypt message or no hidden message found.")

    else:
        print("Invalid operation. Choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
