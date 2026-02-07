"""
Input Validation Utilities
Validates PCAP files, file sizes, and input parameters
"""

import os
import magic  # python-magic for file type detection

def validate_pcap_file(filepath):
    """
    Validate if file is a valid PCAP file
    
    Args:
        filepath (str): Path to file
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Check if file exists
    if not os.path.exists(filepath):
        return False, "File does not exist"
    
    # Check if file is readable
    if not os.path.isfile(filepath):
        return False, "Path is not a file"
    
    # Check file extension
    valid_extensions = ['.pcap', '.pcapng', '.cap']
    file_ext = os.path.splitext(filepath)[1].lower()
    
    if file_ext not in valid_extensions:
        return False, f"Invalid file extension. Expected {', '.join(valid_extensions)}"
    
    # Check file magic bytes (optional - requires python-magic)
    try:
        file_type = magic.from_file(filepath, mime=True)
        # PCAP files usually have application/vnd.tcpdump.pcap or application/octet-stream
        if 'pcap' not in file_type.lower() and 'octet-stream' not in file_type.lower():
            # Try reading with scapy as final check
            from scapy.all import rdpcap
            try:
                packets = rdpcap(filepath, count=1)  # Just read first packet
                return True, None
            except:
                return False, "File is not a valid PCAP format"
    except ImportError:
        # python-magic not installed, skip magic byte check
        pass
    except Exception as e:
        return False, f"File validation error: {str(e)}"
    
    return True, None


def validate_file_size(filepath, max_size_mb=100):
    """
    Validate file size is within limits
    
    Args:
        filepath (str): Path to file
        max_size_mb (int): Maximum allowed size in MB
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not os.path.exists(filepath):
        return False, "File does not exist"
    
    file_size = os.path.getsize(filepath)
    file_size_mb = file_size / (1024 * 1024)
    
    if file_size_mb > max_size_mb:
        return False, f"File too large ({file_size_mb:.2f}MB). Maximum allowed: {max_size_mb}MB"
    
    if file_size == 0:
        return False, "File is empty"
    
    return True, None


def validate_ip_address(ip):
    """
    Validate IP address format
    
    Args:
        ip (str): IP address string
        
    Returns:
        bool: True if valid, False otherwise
    """
    import ipaddress
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_mac_address(mac):
    """
    Validate MAC address format
    
    Args:
        mac (str): MAC address string
        
    Returns:
        bool: True if valid, False otherwise
    """
    import re
    
    # MAC address pattern: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    
    return bool(re.match(pattern, mac))


def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal attacks
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    import re
    
    # Remove path separators
    filename = os.path.basename(filename)
    
    # Remove dangerous characters
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename


def validate_severity_level(severity):
    """
    Validate severity level
    
    Args:
        severity (str): Severity level
        
    Returns:
        bool: True if valid, False otherwise
    """
    valid_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    return severity.upper() in valid_levels