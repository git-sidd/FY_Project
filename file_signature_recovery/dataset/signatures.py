"""
File Signature Database — Real Magic Bytes for Forensic Analysis
================================================================

Each entry contains:
    magic_bytes  : exact hex bytes found at the start of the file (bytes literal)
    offset       : byte offset where the signature appears (0 unless noted)
    extension    : list of valid file extensions for the type
    footer       : end-of-file marker bytes if known, else None
    description  : one-line human readable description
    category     : document | image | video | audio | archive | executable | database | web
"""

SIGNATURES: dict[str, dict] = {
    # ──────────────────────────── DOCUMENTS ────────────────────────────
    "PDF": {
        "magic_bytes": b"\x25\x50\x44\x46\x2D",           # %PDF-
        "offset": 0,
        "extension": [".pdf"],
        "footer": b"\x25\x25\x45\x4F\x46",                # %%EOF
        "description": "Adobe Portable Document Format",
        "category": "document",
    },
    "DOCX": {
        "magic_bytes": b"\x50\x4B\x03\x04",                # PK.. (ZIP-based container)
        "offset": 0,
        "extension": [".docx"],
        "footer": b"\x50\x4B\x05\x06",                    # PK end-of-central-directory
        "description": "Microsoft Word Open XML Document",
        "category": "document",
    },
    "XLSX": {
        "magic_bytes": b"\x50\x4B\x03\x04",                # PK..
        "offset": 0,
        "extension": [".xlsx"],
        "footer": b"\x50\x4B\x05\x06",
        "description": "Microsoft Excel Open XML Spreadsheet",
        "category": "document",
    },
    "PPTX": {
        "magic_bytes": b"\x50\x4B\x03\x04",                # PK..
        "offset": 0,
        "extension": [".pptx"],
        "footer": b"\x50\x4B\x05\x06",
        "description": "Microsoft PowerPoint Open XML Presentation",
        "category": "document",
    },

    # ──────────────────────────── IMAGES ───────────────────────────────
    "PNG": {
        "magic_bytes": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",  # .PNG....
        "offset": 0,
        "extension": [".png"],
        "footer": b"\x49\x45\x4E\x44\xAE\x42\x60\x82",       # IEND....
        "description": "Portable Network Graphics image",
        "category": "image",
    },
    "JPEG": {
        "magic_bytes": b"\xFF\xD8\xFF\xE0",                # JFIF variant
        "offset": 0,
        "extension": [".jpeg", ".jpg"],
        "footer": b"\xFF\xD9",
        "description": "JPEG/JFIF image",
        "category": "image",
    },
    "JPG": {
        "magic_bytes": b"\xFF\xD8\xFF\xE1",                # EXIF variant
        "offset": 0,
        "extension": [".jpg", ".jpeg"],
        "footer": b"\xFF\xD9",
        "description": "JPEG/EXIF image",
        "category": "image",
    },
    "GIF": {
        "magic_bytes": b"\x47\x49\x46\x38",                # GIF8 (covers 87a & 89a)
        "offset": 0,
        "extension": [".gif"],
        "footer": b"\x00\x3B",                             # GIF trailer
        "description": "Graphics Interchange Format image",
        "category": "image",
    },
    "BMP": {
        "magic_bytes": b"\x42\x4D",                         # BM
        "offset": 0,
        "extension": [".bmp", ".dib"],
        "footer": None,
        "description": "Windows Bitmap image",
        "category": "image",
    },
    "TIFF": {
        "magic_bytes": b"\x49\x49\x2A\x00",                # II*. (little-endian)
        "offset": 0,
        "extension": [".tiff", ".tif"],
        "footer": None,
        "description": "Tagged Image File Format (little-endian)",
        "category": "image",
    },
    "TIFF_BE": {
        "magic_bytes": b"\x4D\x4D\x00\x2A",                # MM.* (big-endian)
        "offset": 0,
        "extension": [".tiff", ".tif"],
        "footer": None,
        "description": "Tagged Image File Format (big-endian)",
        "category": "image",
    },
    "WEBP": {
        "magic_bytes": b"\x52\x49\x46\x46",                # RIFF (+ WEBP at offset 8)
        "offset": 0,
        "extension": [".webp"],
        "footer": None,
        "description": "WebP image (RIFF container)",
        "category": "image",
    },

    # ──────────────────────────── AUDIO ────────────────────────────────
    "MP3": {
        "magic_bytes": b"\xFF\xFB",                         # MPEG-1 Layer 3 sync word
        "offset": 0,
        "extension": [".mp3"],
        "footer": None,
        "description": "MPEG-1 Audio Layer 3",
        "category": "audio",
    },
    "MP3_ID3": {
        "magic_bytes": b"\x49\x44\x33",                    # ID3 tag header
        "offset": 0,
        "extension": [".mp3"],
        "footer": None,
        "description": "MPEG-1 Audio Layer 3 with ID3v2 tag",
        "category": "audio",
    },
    "WAV": {
        "magic_bytes": b"\x52\x49\x46\x46",                # RIFF (+ WAVE at offset 8)
        "offset": 0,
        "extension": [".wav"],
        "footer": None,
        "description": "Waveform Audio File Format (RIFF container)",
        "category": "audio",
    },
    "OGG": {
        "magic_bytes": b"\x4F\x67\x67\x53",                # OggS
        "offset": 0,
        "extension": [".ogg", ".oga", ".ogv"],
        "footer": None,
        "description": "Ogg multimedia container",
        "category": "audio",
    },
    "FLAC": {
        "magic_bytes": b"\x66\x4C\x61\x43",                # fLaC
        "offset": 0,
        "extension": [".flac"],
        "footer": None,
        "description": "Free Lossless Audio Codec",
        "category": "audio",
    },

    # ──────────────────────────── VIDEO ────────────────────────────────
    "MP4": {
        "magic_bytes": b"\x66\x74\x79\x70",                # ftyp (at offset 4)
        "offset": 4,
        "extension": [".mp4", ".m4v", ".m4a"],
        "footer": None,
        "description": "MPEG-4 Part 14 multimedia container",
        "category": "video",
    },
    "AVI": {
        "magic_bytes": b"\x52\x49\x46\x46",                # RIFF (+ AVI  at offset 8)
        "offset": 0,
        "extension": [".avi"],
        "footer": None,
        "description": "Audio Video Interleave (RIFF container)",
        "category": "video",
    },

    # ──────────────────────────── ARCHIVES ─────────────────────────────
    "ZIP": {
        "magic_bytes": b"\x50\x4B\x03\x04",                # PK..
        "offset": 0,
        "extension": [".zip"],
        "footer": b"\x50\x4B\x05\x06",
        "description": "ZIP compressed archive",
        "category": "archive",
    },
    "RAR": {
        "magic_bytes": b"\x52\x61\x72\x21\x1A\x07\x00",    # Rar!...  (RAR 4.x)
        "offset": 0,
        "extension": [".rar"],
        "footer": None,
        "description": "RAR compressed archive (v4)",
        "category": "archive",
    },
    "RAR5": {
        "magic_bytes": b"\x52\x61\x72\x21\x1A\x07\x01\x00",# Rar!.... (RAR 5.x)
        "offset": 0,
        "extension": [".rar"],
        "footer": None,
        "description": "RAR compressed archive (v5)",
        "category": "archive",
    },
    "7Z": {
        "magic_bytes": b"\x37\x7A\xBC\xAF\x27\x1C",        # 7z....
        "offset": 0,
        "extension": [".7z"],
        "footer": None,
        "description": "7-Zip compressed archive",
        "category": "archive",
    },
    "TAR": {
        "magic_bytes": b"\x75\x73\x74\x61\x72",             # ustar (at offset 257)
        "offset": 257,
        "extension": [".tar"],
        "footer": None,
        "description": "POSIX tar archive (ustar format)",
        "category": "archive",
    },
    "GZIP": {
        "magic_bytes": b"\x1F\x8B\x08",                     # ...
        "offset": 0,
        "extension": [".gz", ".tar.gz", ".tgz"],
        "footer": None,
        "description": "GZIP compressed file",
        "category": "archive",
    },
    "BZIP2": {
        "magic_bytes": b"\x42\x5A\x68",                     # BZh
        "offset": 0,
        "extension": [".bz2", ".tar.bz2"],
        "footer": None,
        "description": "BZIP2 compressed file",
        "category": "archive",
    },
    "ISO": {
        "magic_bytes": b"\x43\x44\x30\x30\x31",             # CD001 (at offset 0x8001)
        "offset": 0x8001,
        "extension": [".iso"],
        "footer": None,
        "description": "ISO 9660 CD/DVD disc image",
        "category": "archive",
    },

    # ──────────────────────────── EXECUTABLES ──────────────────────────
    "EXE": {
        "magic_bytes": b"\x4D\x5A",                         # MZ
        "offset": 0,
        "extension": [".exe", ".dll", ".sys", ".drv"],
        "footer": None,
        "description": "DOS/Windows MZ executable (PE format)",
        "category": "executable",
    },
    "PE": {
        "magic_bytes": b"\x4D\x5A",                         # MZ header (PE starts at variable offset)
        "offset": 0,
        "extension": [".exe", ".dll", ".sys", ".scr", ".drv"],
        "footer": None,
        "description": "Windows Portable Executable",
        "category": "executable",
    },
    "ELF": {
        "magic_bytes": b"\x7F\x45\x4C\x46",                 # .ELF
        "offset": 0,
        "extension": [".elf", ".so", ".o", ""],
        "footer": None,
        "description": "ELF Unix/Linux executable or shared object",
        "category": "executable",
    },
    "CLASS": {
        "magic_bytes": b"\xCA\xFE\xBA\xBE",                 # Java magic
        "offset": 0,
        "extension": [".class"],
        "footer": None,
        "description": "Java compiled bytecode class file",
        "category": "executable",
    },

    # ──────────────────────────── DATABASE ─────────────────────────────
    "SQLITE": {
        "magic_bytes": b"\x53\x51\x4C\x69\x74\x65\x20\x66"
                       b"\x6F\x72\x6D\x61\x74\x20\x33\x00",# SQLite format 3\0
        "offset": 0,
        "extension": [".sqlite", ".db", ".sqlite3"],
        "footer": None,
        "description": "SQLite database file",
        "category": "database",
    },

    # ──────────────────────────── WEB ──────────────────────────────────
    "XML": {
        "magic_bytes": b"\x3C\x3F\x78\x6D\x6C",            # <?xml
        "offset": 0,
        "extension": [".xml", ".xsl", ".xsd", ".svg"],
        "footer": None,
        "description": "Extensible Markup Language document",
        "category": "web",
    },
    "HTML": {
        "magic_bytes": b"\x3C\x21\x44\x4F\x43\x54\x59\x50\x45",  # <!DOCTYPE
        "offset": 0,
        "extension": [".html", ".htm"],
        "footer": None,
        "description": "HyperText Markup Language document",
        "category": "web",
    },
    "HTML_TAG": {
        "magic_bytes": b"\x3C\x68\x74\x6D\x6C",            # <html
        "offset": 0,
        "extension": [".html", ".htm"],
        "footer": None,
        "description": "HyperText Markup Language document (html tag start)",
        "category": "web",
    },
}


# ─── Convenience helpers ──────────────────────────────────────────────
CATEGORIES = sorted({v["category"] for v in SIGNATURES.values()})

EXTENSION_MAP: dict[str, list[str]] = {}
for _name, _meta in SIGNATURES.items():
    for _ext in _meta["extension"]:
        EXTENSION_MAP.setdefault(_ext, []).append(_name)


def get_signature(name: str) -> dict | None:
    """Return signature dict for a given type name, or None."""
    return SIGNATURES.get(name.upper())


def list_by_category(category: str) -> dict[str, dict]:
    """Return all signatures belonging to the given category."""
    return {k: v for k, v in SIGNATURES.items() if v["category"] == category}


if __name__ == "__main__":
    print(f"Loaded {len(SIGNATURES)} file signatures across {len(CATEGORIES)} categories.")
    for cat in CATEGORIES:
        members = list_by_category(cat)
        print(f"  [{cat}]  {len(members)} types: {', '.join(members.keys())}")
