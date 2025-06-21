import os
from wtforms.validators import ValidationError

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_image_extension(filename):
    """Check if file extension is allowed for images."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


class FileSizeLimit:
    """WTForms validator to limit uploaded file size."""

    def __init__(self, max_bytes: int, message: str | None = None):
        self.max_bytes = max_bytes
        self.message = message or f"File must be smaller than {max_bytes // (1024 * 1024)} MB."

    def __call__(self, form, field):
        data = field.data
        if data:
            data.seek(0, os.SEEK_END)
            size = data.tell()
            data.seek(0)
            if size > self.max_bytes:
                raise ValidationError(self.message)

def validate_file_content(file_storage):
    """
    Validate that uploaded file (werkzeug.FileStorage object) is actually an image
    by checking its magic bytes.
    Resets file pointer to the beginning after reading.
    """
    try:
        # Check file signature (magic bytes)
        file_storage.seek(0)
        header = file_storage.read(512) # Read enough bytes for common image headers
        file_storage.seek(0) # Reset pointer for subsequent operations (e.g., save)

        # Common image file signatures
        # Reference: https://en.wikipedia.org/wiki/List_of_file_signatures
        image_signatures = [
            b'\xff\xd8\xff',        # JPEG (SOI, APPn, ...)
            b'\x89PNG\r\n\x1a\n',  # PNG
            b'GIF87a',            # GIF87a
            b'GIF89a',            # GIF89a
            b'RIFF',              # Start of WebP (RIFF....WEBPVP8)
            # Add more if needed, e.g., for BMP, TIFF, etc.
        ]

        # Special check for WebP as 'RIFF' is too generic
        if header.startswith(b'RIFF') and header[8:12] == b'WEBP':
            return True

        return any(header.startswith(sig) for sig in image_signatures if not sig == b'RIFF') # Exclude generic RIFF here
    except Exception:
        # If any error occurs during file reading, assume it's not a valid/readable image
        return False
