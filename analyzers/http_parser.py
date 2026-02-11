"""
Advanced HTTP Analysis Module
Detects credentials, sensitive data, and security misconfigurations
"""

from scapy.all import rdpcap, TCP, Raw, IP
from datetime import datetime
import re
import base64

def extract_http_credentials(pcap_file):
    """
    Advanced HTTP analysis
    
    Detection Methods:
    1. POST credentials (form data)
    2. Basic Authentication headers
    3. API keys and tokens
    4. Session cookies
    5. Sensitive data in URLs (PII)
    6. Credit card numbers
    7. Social Security Numbers
    """
    print(f"[HTTP Parser] Analyzing {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[HTTP Parser] Error reading PCAP: {e}")
        return []
    
    findings = []
    sessions = {}  # Track HTTP sessions
    
    # Filter HTTP packets (port 80)
    http_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and 
                    (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and 
                    pkt.haslayer(Raw)]
    
    print(f"[HTTP Parser] Found {len(http_packets)} HTTP packets")
    
    for pkt in http_packets:
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            timestamp = datetime.fromtimestamp(float(pkt.time))
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # DETECTION 1: POST/GET requests
            if 'POST' in payload or 'GET' in payload:
                credential_finding = analyze_http_credentials(pkt, payload, timestamp)
                if credential_finding:
                    findings.append(credential_finding)
                
                # DETECTION 2: Sensitive data in payload
                sensitive_finding = detect_sensitive_data(pkt, payload, timestamp)
                if sensitive_finding:
                    findings.append(sensitive_finding)
                
                # DETECTION 3: Basic Authentication
                basic_auth_finding = detect_basic_auth(pkt, payload, timestamp)
                if basic_auth_finding:
                    findings.append(basic_auth_finding)
                
                # DETECTION 4: Session cookies over HTTP
                cookie_finding = detect_insecure_cookies(pkt, payload, timestamp)
                if cookie_finding:
                    findings.append(cookie_finding)
        
        except Exception as e:
            continue
    
    print(f"[HTTP Parser] Analysis complete: {len(findings)} findings")
    return findings


def analyze_http_credentials(pkt, payload, timestamp):
    """Detect username/password in HTTP"""
    
    password_patterns = [
        r'password=([^&\s]+)',
        r'passwd=([^&\s]+)',
        r'pwd=([^&\s]+)',
        r'pass=([^&\s]+)'
    ]
    
    username_patterns = [
        r'username=([^&\s]+)',
        r'user=([^&\s]+)',
        r'email=([^&@\s]+@[^&\s]+)',
        r'login=([^&\s]+)',
        r'uname=([^&\s]+)'
    ]
    
    # Extract method and URL
    method_match = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)', payload)
    if not method_match:
        return None
    
    method = method_match.group(1)
    url = method_match.group(2)
    
    # Extract credentials
    username = None
    password = None
    
    for pattern in username_patterns:
        match = re.search(pattern, payload, re.IGNORECASE)
        if match:
            username = match.group(1)
            break
    
    for pattern in password_patterns:
        match = re.search(pattern, payload, re.IGNORECASE)
        if match:
            password = sanitize_password(match.group(1))
            break
    
    if username or password:
        return {
            'type': 'credential_exposure',
            'severity': 'HIGH',
            'source_ip': pkt[IP].src,
            'destination_ip': pkt[IP].dst,
            'method': method,
            'url': f"http://{extract_host(payload)}{url}",
            'username': username or 'N/A',
            'password': password or 'N/A',
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'mitre_id': 'T1040',
            'attack_type': 'Plaintext Credential Transmission',
            'confidence': 'HIGH'
        }
    
    return None


def detect_basic_auth(pkt, payload, timestamp):
    """Detect HTTP Basic Authentication"""
    
    auth_match = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', payload)
    
    if auth_match:
        try:
            encoded = auth_match.group(1)
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            
            if ':' in decoded:
                username, password = decoded.split(':', 1)
                
                return {
                    'type': 'basic_auth',
                    'severity': 'CRITICAL',
                    'source_ip': pkt[IP].src,
                    'destination_ip': pkt[IP].dst,
                    'method': 'Basic Auth',
                    'url': f"http://{extract_host(payload)}",
                    'username': username,
                    'password': sanitize_password(password),
                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'mitre_id': 'T1040',
                    'attack_type': 'Basic Authentication Over HTTP',
                    'confidence': 'HIGH'
                }
        except:
            pass
    
    return None


def detect_sensitive_data(pkt, payload, timestamp):
    """Detect PII and sensitive data"""
    
    # Credit card pattern (simple validation)
    cc_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'
    
    # SSN pattern
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    
    # API key patterns
    api_patterns = [
        r'(api[_-]?key|apikey)[=:\s]+([a-zA-Z0-9_\-]{20,})',
        r'(sk_live_[a-zA-Z0-9]{24,})',
        r'(bearer\s+[a-zA-Z0-9\-._~+/]+=*)',
        r'(token[=:\s]+[a-zA-Z0-9_\-]{20,})'
    ]
    
    findings = []
    
    # Check for credit cards
    cc_match = re.search(cc_pattern, payload)
    if cc_match:
        return {
            'type': 'pii_exposure',
            'severity': 'CRITICAL',
            'source_ip': pkt[IP].src,
            'destination_ip': pkt[IP].dst,
            'method': 'N/A',
            'url': f"http://{extract_host(payload)}",
            'data_type': 'Credit Card',
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'mitre_id': 'T1040',
            'attack_type': 'PII Exposure',
            'confidence': 'MEDIUM'
        }
    
    # Check for SSN
    ssn_match = re.search(ssn_pattern, payload)
    if ssn_match:
        return {
            'type': 'pii_exposure',
            'severity': 'CRITICAL',
            'source_ip': pkt[IP].src,
            'destination_ip': pkt[IP].dst,
            'method': 'N/A',
            'url': f"http://{extract_host(payload)}",
            'data_type': 'Social Security Number',
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'mitre_id': 'T1040',
            'attack_type': 'PII Exposure',
            'confidence': 'HIGH'
        }
    
    # Check for API keys
    for pattern in api_patterns:
        api_match = re.search(pattern, payload, re.IGNORECASE)
        if api_match:
            api_key = api_match.group(2) if len(api_match.groups()) > 1 else api_match.group(1)
            
            return {
                'type': 'api_key_exposure',
                'severity': 'HIGH',
                'source_ip': pkt[IP].src,
                'destination_ip': pkt[IP].dst,
                'method': 'N/A',
                'url': f"http://{extract_host(payload)}",
                'api_key': sanitize_api_key(api_key),
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'mitre_id': 'T1040',
                'attack_type': 'API Key Exposure',
                'confidence': 'HIGH'
            }
    
    return None


def detect_insecure_cookies(pkt, payload, timestamp):
    """Detect session cookies transmitted over HTTP"""
    
    cookie_pattern = r'Cookie:\s*([^\r\n]+)'
    set_cookie_pattern = r'Set-Cookie:\s*([^\r\n]+)'
    
    # Check for cookies in request
    cookie_match = re.search(cookie_pattern, payload, re.IGNORECASE)
    if cookie_match:
        cookie_value = cookie_match.group(1)
        
        # Check if it's a session cookie
        if any(x in cookie_value.lower() for x in ['session', 'auth', 'token', 'jwt']):
            return {
                'type': 'insecure_cookie',
                'severity': 'MEDIUM',
                'source_ip': pkt[IP].src,
                'destination_ip': pkt[IP].dst,
                'method': 'Cookie',
                'url': f"http://{extract_host(payload)}",
                'cookie': cookie_value[:50] + '...' if len(cookie_value) > 50 else cookie_value,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'mitre_id': 'T1539',  # Steal Web Session Cookie
                'attack_type': 'Insecure Session Cookie',
                'confidence': 'MEDIUM'
            }
    
    # Check for Set-Cookie in response
    set_cookie_match = re.search(set_cookie_pattern, payload, re.IGNORECASE)
    if set_cookie_match:
        cookie_value = set_cookie_match.group(1)
        
        # Check if Secure flag is missing
        if 'secure' not in cookie_value.lower():
            return {
                'type': 'insecure_cookie',
                'severity': 'LOW',
                'source_ip': pkt[IP].src,
                'destination_ip': pkt[IP].dst,
                'method': 'Set-Cookie',
                'url': f"http://{extract_host(payload)}",
                'cookie': 'Missing Secure flag',
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'mitre_id': 'T1539',
                'attack_type': 'Cookie Without Secure Flag',
                'confidence': 'LOW'
            }
    
    return None


def extract_host(payload):
    """Extract Host header from HTTP request"""
    match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
    return match.group(1).strip() if match else 'unknown.host'


def sanitize_password(password):
    """Sanitize password for display"""
    password = password[:100]  # Limit length
    if len(password) <= 4:
        return '****'
    return f"{password[:2]}****{password[-2:]}"


def sanitize_api_key(api_key):
    """Sanitize API key for display"""
    if len(api_key) <= 10:
        return api_key[:3] + '***'
    return api_key[:8] + '***'
