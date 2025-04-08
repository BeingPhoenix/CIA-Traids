# integrity.py
import hmac
import hashlib

def compute_hmac(file_path: str, key: bytes) -> str:
    """
    Compute HMAC-SHA256 of the file contents using the provided key.
    Returns the hex digest of the HMAC.
    """
    h = hmac.new(key, digestmod=hashlib.sha256)
    with open(file_path, "rb") as f:
        # Process file in chunks for large files
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_hmac(file_path: str, expected_hmac: str, key: bytes) -> bool:
    """
    Verify the HMAC for a given file.
    """
    computed = compute_hmac(file_path, key)
    return hmac.compare_digest(computed, expected_hmac)
