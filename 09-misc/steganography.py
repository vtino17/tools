#!/usr/bin/env python3
"""
Steganography Tool - Hide/Extract data in images
Mendukung LSB steganography pada file gambar.
Usage:
  Hide: python steganography.py hide -i input.png -d secret.txt -o output.png
  Extract: python steganography.py extract -i output.png -o secret_extracted.txt
"""

import argparse
import sys
import os


def text_to_binary(text):
    return "".join(format(ord(c), "08b") for c in text)


def binary_to_text(binary):
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i : i + 8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return "".join(chars)


def hide_data_lsb(input_image, data, output_image):
    """Hide data using LSB steganography"""
    try:
        from PIL import Image
    except ImportError:
        print("[!] Install Pillow: pip install pillow")
        return False

    img = Image.open(input_image)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = img.load()
    width, height = img.size

    # Add end marker
    data_to_hide = data + chr(0)
    binary_data = text_to_binary(data_to_hide)

    if len(binary_data) > width * height * 3:
        print(f"[!] Data too large for image. Max: {width * height * 3 // 8} bytes")
        return False

    data_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            new_rgb = [r, g, b]
            for i in range(3):
                if data_index < len(binary_data):
                    # Modify LSB
                    new_rgb[i] = (new_rgb[i] & 0xFE) | int(binary_data[data_index])
                    data_index += 1
            pixels[x, y] = tuple(new_rgb)
            if data_index >= len(binary_data):
                break
        if data_index >= len(binary_data):
            break

    img.save(output_image)
    return True


def extract_data_lsb(image_path):
    """Extract hidden data from image"""
    try:
        from PIL import Image
    except ImportError:
        print("[!] Install Pillow: pip install pillow")
        return None

    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = img.load()
    width, height = img.size

    binary_data = ""
    found_null = False
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            for color in [r, g, b]:
                binary_data += str(color & 1)
                if len(binary_data) % 8 == 0:
                    byte = binary_data[-8:]
                    char = chr(int(byte, 2))
                    if char == chr(0):
                        found_null = True
                        break
            if found_null:
                break
        if found_null:
            break

    return binary_to_text(binary_data)


def main():
    parser = argparse.ArgumentParser(description="Steganography Tool")
    sub = parser.add_subparsers(dest="mode", required=True)

    hide = sub.add_parser("hide", help="Hide data in image")
    hide.add_argument("-i", "--image", required=True, help="Input image")
    hide.add_argument("-d", "--data", help="Text data to hide")
    hide.add_argument("-f", "--file", help="File to hide (use instead of -d)")
    hide.add_argument("-o", "--output", required=True, help="Output image")

    extract = sub.add_parser("extract", help="Extract data from image")
    extract.add_argument("-i", "--image", required=True, help="Image with hidden data")
    extract.add_argument("-o", "--output", help="Save extracted data to file")

    args = parser.parse_args()

    if args.mode == "hide":
        if not os.path.exists(args.image):
            print(f"[!] Image not found: {args.image}")
            sys.exit(1)

        if args.data:
            data = args.data
        elif args.file:
            if not os.path.exists(args.file):
                print(f"[!] File not found: {args.file}")
                sys.exit(1)
            with open(args.file, "r", errors="ignore") as f:
                data = f.read()
        else:
            print("[!] Butuh -d atau -f")
            sys.exit(1)

        print(f"[*] Hiding {len(data)} bytes in {args.image}")
        if hide_data_lsb(args.image, data, args.output):
            print(f"[+] Data hidden in: {args.output}")

    elif args.mode == "extract":
        if not os.path.exists(args.image):
            print(f"[!] Image not found: {args.image}")
            sys.exit(1)

        print(f"[*] Extracting from {args.image}")
        data = extract_data_lsb(args.image)
        if data is not None:
            if args.output:
                with open(args.output, "w") as f:
                    f.write(data)
                print(f"[+] Data extracted to: {args.output}")
            else:
                print("[+] Extracted data:")
                print("-" * 60)
                print(data[:500])
                if len(data) > 500:
                    print(f"... ({len(data) - 500} more chars)")


if __name__ == "__main__":
    main()
