"""
Payload Decoding Utilities
Decodes Base64, URL-encoded, and hex-encoded data
"""

import base64
import urllib.parse
import binascii

def decode_base64(encoded_string):
    """
    Decode Base64 encoded string
    
    Args:
        encoded_string (str): Base64 encoded string
        
    Returns:
        str: Decoded string or None if decoding fails
    """
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
        return decoded_string
    except Exception as e:
        print(f"[Decoder] Base64 decode error: {e}")
        return None


def decode_url(encoded_string):
    """
    Decode URL-encoded string
    
    Args:
        encoded_string (str): URL-encoded string
        
    Returns:
        str: Decoded string
    """
    try:
        decoded_string = urllib.parse.unquote(encoded_string)
        return decoded_string
    except Exception as e:
        print(f"[Decoder] URL decode error: {e}")
        return encoded_string


def decode_hex(hex_string):
    """
    Decode hex-encoded string
    
    Args:
        hex_string (str): Hex-encoded string
        
    Returns:
        str: Decoded string or None if decoding fails
    """
    try:
        # Remove any whitespace and convert to bytes
        hex_string = hex_string.replace(' ', '').replace('0x', '')
        decoded_bytes = bytes.fromhex(hex_string)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
        return decoded_string
    except Exception as e:
        print(f"[Decoder] Hex decode error: {e}")
        return None


def decode_base32(encoded_string):
    """
    Decode Base32 encoded string
    
    Args:
        encoded_string (str): Base32 encoded string
        
    Returns:
        str: Decoded string or None if decoding fails
    """
    try:
        decoded_bytes = base64.b32decode(encoded_string)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
        return decoded_string
    except Exception as e:
        print(f"[Decoder] Base32 decode error: {e}")
        return None


def auto_decode(encoded_string):
    """
    Automatically detect and decode encoded string
    
    Args:
        encoded_string (str): Encoded string
        
    Returns:
        dict: Dictionary with decoding results
    """
    results = {
        'original': encoded_string,
        'base64': None,
        'url': None,
        'hex': None,
        'base32': None
    }
    
    # Try Base64
    base64_decoded = decode_base64(encoded_string)
    if base64_decoded and base64_decoded != encoded_string:
        results['base64'] = base64_decoded
    
    # Try URL decode
    url_decoded = decode_url(encoded_string)
    if url_decoded != encoded_string:
        results['url'] = url_decoded
    
    # Try Hex
    hex_decoded = decode_hex(encoded_string)
    if hex_decoded and hex_decoded != encoded_string:
        results['hex'] = hex_decoded
    
    # Try Base32
    base32_decoded = decode_base32(encoded_string)
    if base32_decoded and base32_decoded != encoded_string:
        results['base32'] = base32_decoded
    
    return results


def extract_encoded_strings(text):
    """
    Extract potentially encoded strings from text
    
    Args:
        text (str): Text to analyze
        
    Returns:
        list: List of potentially encoded strings
    """
    import re
    
    encoded_patterns = [
        r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
        r'%[0-9A-Fa-f]{2}',            # URL encoded
        r'(?:0x)?[0-9A-Fa-f]{20,}',    # Hex
        r'[A-Z2-7]{20,}={0,6}'         # Base32
    ]
    
    encoded_strings = []
    
    for pattern in encoded_patterns:
        matches = re.findall(pattern, text)
        encoded_strings.extend(matches)
    
    return list(set(encoded_strings))  # Remove duplicates


def is_likely_encoded(string, min_length=10):
    """
    Check if string is likely encoded
    
    Args:
        string (str): String to check
        min_length (int): Minimum length to consider
        
    Returns:
        dict: Encoding likelihood scores
    """
    import re
    
    if len(string) < min_length:
        return {
            'base64': False,
            'url': False,
            'hex': False,
            'base32': False
        }
    
    likelihood = {
        'base64': bool(re.match(r'^[A-Za-z0-9+/]+=*$', string)),
        'url': '%' in string and bool(re.search(r'%[0-9A-Fa-f]{2}', string)),
        'hex': bool(re.match(r'^(?:0x)?[0-9A-Fa-f]+$', string)),
        'base32': bool(re.match(r'^[A-Z2-7]+=*$', string.upper()))
    }
    
    return likelihood