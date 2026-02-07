"""
Advanced DNS Exfiltration Detection
Detects DNS tunneling, C2 communication, and DGA domains
"""

from scapy.all import rdpcap, DNS, DNSQR, DNSRR
from datetime import datetime
from collections import defaultdict, Counter
import math
import re

def detect_dns_exfiltration(pcap_file):
    """
    Advanced DNS analysis
    
    Detection Methods:
    1. Long query detection (>50 chars)
    2. High entropy subdomains
    3. Base64/Base32/Hex encoding
    4. Query frequency analysis
    5. Subdomain count analysis
    6. TXT record anomalies
    7. Uncommon TLDs
    8. DGA (Domain Generation Algorithm) detection
    """
    print(f"[DNS Analyzer] Analyzing {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[DNS Analyzer] Error reading PCAP: {e}")
        return []
    
    dns_queries = []
    domain_stats = defaultdict(lambda: {
        'queries': 0,
        'lengths': [],
        'subdomains': set(),
        'timestamps': []
    })
    
    txt_records = []
    
    # Extract DNS queries and responses
    for pkt in packets:
        if pkt.haslayer(DNS):
            timestamp = datetime.fromtimestamp(float(pkt.time))
            
            # Queries
            if pkt.haslayer(DNSQR) and pkt[DNS].qd:
                query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                qtype = pkt[DNS].qd.qtype  # 1=A, 16=TXT, etc.
                
                dns_queries.append({
                    'query': query,
                    'timestamp': timestamp,
                    'length': len(query),
                    'qtype': qtype
                })
                
                # Extract base domain
                domain_parts = query.split('.')
                if len(domain_parts) >= 2:
                    base_domain = '.'.join(domain_parts[-2:])
                    subdomain = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else ''
                    
                    domain_stats[base_domain]['queries'] += 1
                    domain_stats[base_domain]['lengths'].append(len(query))
                    if subdomain:
                        domain_stats[base_domain]['subdomains'].add(subdomain)
                    domain_stats[base_domain]['timestamps'].append(timestamp)
                
                # Track TXT queries
                if qtype == 16:  # TXT record
                    txt_records.append({
                        'query': query,
                        'timestamp': timestamp
                    })
            
            # Responses (for TXT analysis)
            if pkt.haslayer(DNSRR):
                for i in range(pkt[DNS].ancount):
                    rr = pkt[DNS].an[i]
                    if rr.type == 16:  # TXT record
                        txt_records.append({
                            'query': rr.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                            'timestamp': timestamp,
                            'response': True
                        })
    
    print(f"[DNS Analyzer] Found {len(dns_queries)} DNS queries")
    print(f"[DNS Analyzer] Found {len(txt_records)} TXT records")
    
    findings = []
    analyzed_domains = set()
    
    # Analyze each query
    for query_info in dns_queries:
        query = query_info['query']
        timestamp = query_info['timestamp']
        length = query_info['length']
        qtype = query_info['qtype']
        
        # Skip if already analyzed this domain
        if query in analyzed_domains:
            continue
        
        suspicious_indicators = []
        severity = 'LOW'
        confidence = 'LOW'
        
        # DETECTION 1: Long query
        if length > 50:
            suspicious_indicators.append(f'Long query ({length} chars)')
            severity = 'MEDIUM'
            confidence = 'MEDIUM'
        
        # Extract subdomain for analysis
        domain_parts = query.split('.')
        subdomain = domain_parts[0] if domain_parts else query
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else query
        
        # DETECTION 2: High entropy
        if len(subdomain) > 10:
            entropy = calculate_entropy(subdomain)
            if entropy > 3.5:
                suspicious_indicators.append(f'High entropy ({entropy:.2f})')
                severity = 'MEDIUM'
                confidence = 'MEDIUM'
        
        # DETECTION 3: Encoding detection
        if is_base64_encoded(subdomain):
            suspicious_indicators.append('Base64 encoding detected')
            severity = 'HIGH'
            confidence = 'HIGH'
        
        if is_base32_encoded(subdomain):
            suspicious_indicators.append('Base32 encoding detected')
            severity = 'HIGH'
            confidence = 'HIGH'
        
        if is_hex_encoded(subdomain):
            suspicious_indicators.append('Hex encoding detected')
            severity = 'MEDIUM'
            confidence = 'MEDIUM'
        
        # DETECTION 4: Excessive subdomains
        stats = domain_stats.get(base_domain, {})
        subdomain_count = len(stats.get('subdomains', set()))
        if subdomain_count > 10:
            suspicious_indicators.append(f'Excessive subdomains ({subdomain_count})')
            severity = 'HIGH'
            confidence = 'HIGH'
        
        # DETECTION 5: Query frequency
        query_count = stats.get('queries', 0)
        if query_count > 50:
            suspicious_indicators.append(f'High frequency ({query_count} queries)')
            severity = 'HIGH'
            confidence = 'HIGH'
        
        # DETECTION 6: TXT record queries (common for tunneling)
        if qtype == 16:
            suspicious_indicators.append('TXT record query')
            severity = 'HIGH'
            confidence = 'MEDIUM'
        
        # DETECTION 7: Uncommon TLD
        tld = domain_parts[-1] if domain_parts else ''
        if tld in ['tk', 'xyz', 'top', 'ml', 'ga', 'cf', 'gq']:
            suspicious_indicators.append(f'Suspicious TLD (.{tld})')
            severity = 'MEDIUM'
            confidence = 'MEDIUM'
        
        # DETECTION 8: DGA detection (numeric patterns)
        if detect_dga(subdomain):
            suspicious_indicators.append('Possible DGA domain')
            severity = 'HIGH'
            confidence = 'MEDIUM'
        
        # DETECTION 9: Beaconing detection
        if is_beaconing(stats.get('timestamps', [])):
            suspicious_indicators.append('Regular beaconing detected')
            severity = 'HIGH'
            confidence = 'HIGH'
        
        # Create finding if suspicious
        if suspicious_indicators:
            avg_length = int(sum(stats.get('lengths', [length])) / len(stats.get('lengths', [length])))
            
            finding = {
                'type': 'dns_exfiltration',
                'severity': severity,
                'domain': query,
                'query_count': query_count,
                'avg_length': avg_length,
                'entropy': round(calculate_entropy(subdomain), 2) if len(subdomain) > 0 else 0,
                'pattern': ', '.join(suspicious_indicators),
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'mitre_id': 'T1048.003',
                'attack_type': 'DNS Tunneling/Exfiltration',
                'confidence': confidence,
                'qtype': 'TXT' if qtype == 16 else 'A'
            }
            
            findings.append(finding)
            analyzed_domains.add(query)
            print(f"[DNS Analyzer] 🌐 Suspicious: {query} - {', '.join(suspicious_indicators)}")
    
    # Additional TXT record analysis
    if len(txt_records) > 5:
        finding = {
            'type': 'txt_record_abuse',
            'severity': 'MEDIUM',
            'domain': 'Multiple',
            'query_count': len(txt_records),
            'avg_length': 0,
            'entropy': 0,
            'pattern': f'{len(txt_records)} TXT record queries detected',
            'timestamp': txt_records[0]['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'mitre_id': 'T1048.003',
            'attack_type': 'TXT Record Tunneling',
            'confidence': 'MEDIUM',
            'qtype': 'TXT'
        }
        findings.append(finding)
    
    print(f"[DNS Analyzer] Analysis complete: {len(findings)} findings")
    return findings


def calculate_entropy(string):
    """Calculate Shannon entropy"""
    if not string:
        return 0
    
    freq = Counter(string)
    length = len(string)
    
    entropy = 0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def is_base64_encoded(string):
    """Check for Base64 encoding"""
    if len(string) < 10:
        return False
    
    base64_pattern = r'^[A-Za-z0-9+/]+=*$'
    return bool(re.match(base64_pattern, string)) and calculate_entropy(string) > 3.0


def is_base32_encoded(string):
    """Check for Base32 encoding"""
    if len(string) < 10:
        return False
    
    base32_pattern = r'^[A-Z2-7]+=*$'
    return bool(re.match(base32_pattern, string.upper())) and calculate_entropy(string) > 2.5


def is_hex_encoded(string):
    """Check for Hex encoding"""
    if len(string) < 10:
        return False
    
    hex_pattern = r'^[0-9a-fA-F]+$'
    return bool(re.match(hex_pattern, string)) and len(string) % 2 == 0


def detect_dga(subdomain):
    """Detect Domain Generation Algorithm patterns"""
    if len(subdomain) < 8:
        return False
    
    # Check for excessive consonants or numbers
    consonants = sum(1 for c in subdomain if c.lower() in 'bcdfghjklmnpqrstvwxyz')
    numbers = sum(1 for c in subdomain if c.isdigit())
    
    consonant_ratio = consonants / len(subdomain)
    number_ratio = numbers / len(subdomain)
    
    # DGA domains often have high consonant ratio or mixed numbers
    return consonant_ratio > 0.7 or (number_ratio > 0.3 and consonant_ratio > 0.4)


def is_beaconing(timestamps):
    """Detect regular beaconing patterns"""
    if len(timestamps) < 5:
        return False
    
    # Calculate time intervals
    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(delta)
    
    if not intervals:
        return False
    
    # Check if intervals are regular (within 20% variance)
    avg_interval = sum(intervals) / len(intervals)
    
    if avg_interval == 0:
        return False
    
    regular_count = sum(1 for interval in intervals 
                       if abs(interval - avg_interval) / avg_interval < 0.2)
    
    # If >70% of intervals are regular, it's beaconing
    return regular_count / len(intervals) > 0.7