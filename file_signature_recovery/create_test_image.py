import os

# Create a 2MB disk image
sector_size = 512
total_sectors = 4000
image_path = "test_image.dd"

def create_image():
    with open(image_path, "wb") as f:
        # Write zeros for the whole image first
        f.write(b"\x00" * (sector_size * total_sectors))
        
        # 1. Embed a fake PDF at sector 100
        # Offset: 100 * 512 = 51200
        f.seek(100 * sector_size)
        fake_pdf = b"%PDF-1.4\n%Fake PDF for testing recovery\n"
        fake_pdf += b"A" * 1024 # padding
        fake_pdf += b"\n%%EOF"
        f.write(fake_pdf)
        
        # 2. Embed a fake PNG at sector 500
        # Offset: 500 * 512 = 256000
        f.seek(500 * sector_size)
        fake_png_magic = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        fake_png_footer = b"\x49\x45\x4e\x44\xae\x42\x60\x82"
        fake_png = fake_png_magic + (b"B" * 2048) + fake_png_footer
        f.write(fake_png)
        
        # 3. Embed a fake ZIP at sector 2000
        f.seek(2000 * sector_size)
        fake_zip_magic = b"\x50\x4b\x03\x04"
        fake_zip_footer = b"\x50\x4b\x05\x06"
        fake_zip = fake_zip_magic + (b"C" * 4096) + fake_zip_footer
        f.write(fake_zip)

    print(f"Created {image_path} with {total_sectors * sector_size} bytes.")
    print("It contains a fake PDF (sector 100), PNG (sector 500), and ZIP (sector 2000).")

if __name__ == "__main__":
    create_image()
