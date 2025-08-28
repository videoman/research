import hashlib
import base64
import struct

def test_broadcom_variants(password):
    """Test variants common in Broadcom/embedded systems"""

    results = {}
    password_bytes = password.encode('utf-8')

    # Standard variants
    results['plain_sha512'] = hashlib.sha512(password_bytes).hexdigest()
    results['plain_sha256'] = hashlib.sha256(password_bytes).hexdigest()

    # UTF-16 variants (common in embedded systems)
    results['utf16_le'] = hashlib.sha512(password.encode('utf-16le')).hexdigest()
    results['utf16_be'] = hashlib.sha512(password.encode('utf-16be')).hexdigest()

    # Null-terminated string (C-style, common in embedded)
    null_term = password_bytes + b'\x00'
    results['null_terminated'] = hashlib.sha512(null_term).hexdigest()

    # Double null-terminated (sometimes used for wide strings)
    double_null = password_bytes + b'\x00\x00'
    results['double_null'] = hashlib.sha512(double_null).hexdigest()

    # Base64 then hash (common in web interfaces)
    b64 = base64.b64encode(password_bytes)
    results['b64_sha512'] = hashlib.sha512(b64).hexdigest()

    # Hex then hash
    hex_bytes = password_bytes.hex().encode('utf-8')
    results['hex_sha512'] = hashlib.sha512(hex_bytes).hexdigest()

    # Common embedded system patterns
    # Sometimes systems pad to word boundaries (4 or 8 bytes)
    padded_4 = password_bytes + b'\x00' * ((4 - len(password_bytes) % 4) % 4)
    results['padded_4byte'] = hashlib.sha512(padded_4).hexdigest()

    padded_8 = password_bytes + b'\x00' * ((8 - len(password_bytes) % 8) % 8)
    results['padded_8byte'] = hashlib.sha512(padded_8).hexdigest()

    # Some systems convert to uppercase before hashing
    results['uppercase'] = hashlib.sha512(password.upper().encode('utf-8')).hexdigest()

    # Web form encoding
    url_encoded = password.replace(' ', '+').encode('utf-8')  # Basic URL encoding
    results['url_encoded'] = hashlib.sha512(url_encoded).hexdigest()

    return results

# Test it
password = "test1234"
known_hash = "8c7945167990643a9ba652ba7e0663aa5b040a49bd859fbe09efd4892f01fa0a5ce79e40fbebabf41653306942e3db30532ba962108cb4de555abfe07f90a771"

variants = test_broadcom_variants(password)

print(f"Testing password: {password}")
print(f"Target hash: {known_hash}")
print(f"Hash length: {len(known_hash)} characters")
print("\nBroadcom/Embedded variants:")
for variant, hash_value in variants.items():
    match = "✓ MATCH!" if hash_value == known_hash else "✗"
    print(f"{variant:15}: {hash_value} {match}")

