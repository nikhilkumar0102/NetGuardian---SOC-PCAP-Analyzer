"""
Threat Intelligence Module
Integrates with external APIs to provide context on findings.
"""

import requests
import hashlib
import os

# Configuration
# Read key dynamically in functions to support runtime updates

def check_ip_reputation(ip):
    """
    Get IP reputation and geolocation from ip-api.com (Free)
    And VirusTotal (if key exists)
    """
    vt_key = os.environ.get('VT_API_KEY', '')
    
    result = {
        'ip': ip,
        'geolocation': 'Unknown',
        'isp': 'Unknown',
        'country_code': 'XX',
        'reputation': 'Unknown',
        'virustotal_score': 'N/A'
    }

    # 1. Geolocation via ip-api.com
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                result['geolocation'] = f"{data.get('city', '')}, {data.get('country', '')}"
                result['country_code'] = data.get('countryCode', 'XX').lower()
                result['isp'] = data.get('isp', 'Unknown')
    except Exception as e:
        print(f"[ThreatIntel] IP-API Error: {e}")

    # 2. VirusTotal Check (if key exists)
    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": vt_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    result['reputation'] = 'Malicious'
                    result['virustotal_score'] = f"{malicious} vendors flagged"
                elif suspicious > 0:
                    result['reputation'] = 'Suspicious'
                    result['virustotal_score'] = f"{suspicious} vendors suspicious"
                else:
                    result['reputation'] = 'Clean'
                    result['virustotal_score'] = "Clean"
        except Exception as e:
            print(f"[ThreatIntel] VT IP Error: {e}")

    return result

def check_file_hash(filepath):
    """
    Calculate file hash and check against VirusTotal
    """
    vt_key = os.environ.get('VT_API_KEY', '')
    if not vt_key:
        return {'score': 'N/A - No API Key', 'details': 'Configure VT API Key'}

    try:
        # Calculate SHA-256
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Check VT
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": vt_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            
            return {
                'hash': file_hash,
                'malicious_count': malicious,
                'total_vendors': sum(stats.values()),
                'scan_date': data['data']['attributes'].get('last_analysis_date', 'Unknown'),
                'permalink': data['data']['links']['self']
            }
        elif response.status_code == 404:
            return {'score': 'Unknown', 'details': 'File not found in VT database'}
        else:
            return {'score': 'Error', 'details': f'API Error: {response.status_code}'}

    except Exception as e:
        print(f"[ThreatIntel] VT File Error: {e}")
        return {'score': 'Error', 'details': str(e)}

def check_domain_reputation(domain):
    """
    Check domain reputation on VirusTotal
    """
    vt_key = os.environ.get('VT_API_KEY', '')
    
    result = {
        'domain': domain,
        'reputation': 'Unknown',
        'virustotal_score': 'N/A',
        'categories': []
    }
    
    if not vt_key:
        return result

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            # Get categories
            cats = attributes.get('categories', {})
            result['categories'] = list(set(cats.values()))[:3] # Top 3 categories
            
            if malicious > 0:
                result['reputation'] = 'Malicious'
                result['virustotal_score'] = f"{malicious} flagged"
            elif suspicious > 0:
                result['reputation'] = 'Suspicious'
                result['virustotal_score'] = f"{suspicious} suspicious"
            else:
                result['reputation'] = 'Clean'
                result['virustotal_score'] = "Clean"
                
    except Exception as e:
        print(f"[ThreatIntel] VT Domain Error: {e}")
        
    return result
