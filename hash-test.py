import hashlib
import base64
import struct

def test_endianness_variants(password):
    """Test different endianness variants with SHA-512"""

    results = {}
    password_bytes = password.encode('utf-8')

    # Standard SHA-512
    results['plain'] = hashlib.sha512(password_bytes).hexdigest()

    # UTF-16 Little Endian (common on Windows/Intel)
    results['utf16_le'] = hashlib.sha512(password.encode('utf-16le')).hexdigest()

    # UTF-16 Big Endian
    results['utf16_be'] = hashlib.sha512(password.encode('utf-16be')).hexdigest()

    # UTF-32 Little Endian
    results['utf32_le'] = hashlib.sha512(password.encode('utf-32le')).hexdigest()

    # UTF-32 Big Endian
    results['utf32_be'] = hashlib.sha512(password.encode('utf-32be')).hexdigest()

    # Manually swap byte order of the password
    if len(password_bytes) % 2 == 0:  # Only if even number of bytes
        swapped = b''.join(password_bytes[i+1:i+2] + password_bytes[i:i+1]
                          for i in range(0, len(password_bytes), 2))
        results['byte_swapped'] = hashlib.sha512(swapped).hexdigest()

    # Base64 with different encodings
    b64_password = base64.b64encode(password_bytes).decode('utf-8')
    results['b64_utf16le'] = hashlib.sha512(b64_password.encode('utf-16le')).hexdigest()
    results['b64_utf16be'] = hashlib.sha512(b64_password.encode('utf-16be')).hexdigest()

    # Hex encoding with different endianness interpretations
    hex_password = password_bytes.hex()
    results['hex_plain'] = hashlib.sha512(hex_password.encode('utf-8')).hexdigest()
    results['hex_utf16le'] = hashlib.sha512(hex_password.encode('utf-16le')).hexdigest()

    # Try interpreting password as little-endian integers and re-encoding
    if len(password) >= 4:
        try:
            # Pack as little-endian 32-bit integers, then unpack as big-endian
            packed_le = struct.pack('<I', int.from_bytes(password_bytes[:4], 'little'))
            results['int32_swap'] = hashlib.sha512(packed_le).hexdigest()
        except:
            pass

    return results

# Test it
password = "test1234"
known_hash = "8c7945167990643a9ba652ba7e0663aa5b040a49bd859fbe09efd4892f01fa0a5ce79e40fbebabf41653306942e3db30532ba962108cb4de555abfe07f90a771"

variants = test_endianness_variants(password)

print(f"Testing password: {password}")
print(f"Known hash: {known_hash}")
print("\nEndianness variants:")
for variant, hash_value in variants.items():
    match = "✓ MATCH!" if hash_value == known_hash else "✗"
    print(f"{variant:15}: {hash_value} {match}")

