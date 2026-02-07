"""
Advanced ARP Poisoning Detection Module
Detects ARP spoofing, MITM attacks, and network reconnaissance
"""

from scapy.all import rdpcap, ARP, Ether
from datetime import datetime
from collections import defaultdict
import ipaddress

def detect_arp_poisoning(pcap_file):
    """
    Advanced ARP poisoning detection with multiple techniques
    
    Detection Methods:
    1. MAC address changes for same IP
    2. Gratuitous ARP detection
    3. ARP reply storms
    4. Duplicate IP detection
    5. Gateway impersonation
    """
    print(f"[ARP Detector] Analyzing {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ARP Detector] Error reading PCAP: {e}")
        return []
    
    # Data structures
    arp_table = {}  # {IP: MAC}
    arp_history = defaultdict(list)  # {IP: [(MAC, timestamp, packet_num)]}
    mac_to_ips = defaultdict(set)  # {MAC: set(IPs)}
    arp_replies = defaultdict(int)  # Count ARP replies per IP
    gratuitous_arps = []
    findings = []
    
    # Get all ARP packets
    arp_packets = [pkt for pkt in packets if pkt.haslayer(ARP)]
    print(f"[ARP Detector] Found {len(arp_packets)} ARP packets")
    
    if len(arp_packets) == 0:
        print("[ARP Detector] No ARP packets found")
        return []
    
    # Analyze ARP packets
    for idx, pkt in enumerate(arp_packets):
        arp = pkt[ARP]
        
        # Extract information
        ip = arp.psrc
        mac = arp.hwsrc
        target_ip = arp.pdst
        target_mac = arp.hwdst
        op = arp.op  # 1=request, 2=reply
        timestamp = datetime.fromtimestamp(float(pkt.time))
        
        # Skip invalid entries
        if not ip or not mac or ip == '0.0.0.0':
            continue
        
        # Track history
        arp_history[ip].append((mac, timestamp, idx))
        mac_to_ips[mac].add(ip)
        
        # Count ARP replies
        if op == 2:  # ARP Reply
            arp_replies[ip] += 1
        
        # Detect gratuitous ARP (sender IP == target IP)
        if op == 2 and ip == target_ip:
            gratuitous_arps.append({
                'ip': ip,
                'mac': mac,
                'timestamp': timestamp,
                'packet_num': idx
            })
        
        # DETECTION 1: MAC address change (ARP spoofing)
        if ip in arp_table and arp_table[ip] != mac:
            old_mac = arp_table[ip]
            
            # Calculate metrics
            ip_history = arp_history[ip]
            duration_seconds = (timestamp - ip_history[0][1]).total_seconds()
            packet_count = len([h for h in ip_history if h[0] == mac])
            
            # Check if this is likely a gateway (common target)
            is_gateway = is_likely_gateway(ip)
            
            severity = 'CRITICAL' if is_gateway else 'HIGH'
            
            finding = {
                'type': 'arp_spoofing',
                'severity': severity,
                'ip': ip,
                'target_ip': target_ip,
                'old_mac': old_mac,
                'new_mac': mac,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'packet_count': packet_count,
                'duration': format_duration(duration_seconds),
                'is_gateway': is_gateway,
                'attack_type': 'Gateway Impersonation' if is_gateway else 'Host Spoofing',
                'mitre_id': 'T1557.002',
                'confidence': 'HIGH'
            }
            
            findings.append(finding)
            print(f"[ARP Detector] ⚠️  ARP Spoofing: {ip} ({old_mac} → {mac})")
        
        # Update ARP table
        arp_table[ip] = mac
    
    # DETECTION 2: ARP Reply Storm (potential DoS or scanning)
    for ip, count in arp_replies.items():
        if count > 50:  # More than 50 replies
            finding = {
                'type': 'arp_storm',
                'severity': 'MEDIUM',
                'ip': ip,
                'target_ip': 'Multiple',
                'old_mac': 'N/A',
                'new_mac': arp_table.get(ip, 'Unknown'),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'packet_count': count,
                'duration': 'Unknown',
                'is_gateway': False,
                'attack_type': 'ARP Reply Storm',
                'mitre_id': 'T1498',  # Network DoS
                'confidence': 'MEDIUM'
            }
            findings.append(finding)
            print(f"[ARP Detector] 🌪️  ARP Storm: {ip} ({count} replies)")
    
    # DETECTION 3: One MAC claiming multiple IPs (ARP poisoning indicator)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 5:  # One MAC address for >5 IPs
            finding = {
                'type': 'multi_ip_claim',
                'severity': 'HIGH',
                'ip': ', '.join(list(ips)[:3]) + '...',
                'target_ip': 'Multiple',
                'old_mac': 'N/A',
                'new_mac': mac,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'packet_count': len(ips),
                'duration': 'N/A',
                'is_gateway': False,
                'attack_type': 'Multiple IP Claims',
                'mitre_id': 'T1557.002',
                'confidence': 'MEDIUM'
            }
            findings.append(finding)
            print(f"[ARP Detector] 🚨 Multi-IP Claim: {mac} claims {len(ips)} IPs")
    
    # DETECTION 4: Excessive gratuitous ARPs (reconnaissance)
    if len(gratuitous_arps) > 20:
        finding = {
            'type': 'gratuitous_arp_flood',
            'severity': 'MEDIUM',
            'ip': 'Multiple',
            'target_ip': 'Broadcast',
            'old_mac': 'N/A',
            'new_mac': 'Multiple',
            'timestamp': gratuitous_arps[0]['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'packet_count': len(gratuitous_arps),
            'duration': 'Unknown',
            'is_gateway': False,
            'attack_type': 'Network Reconnaissance',
            'mitre_id': 'T1046',  # Network Service Scanning
            'confidence': 'LOW'
        }
        findings.append(finding)
        print(f"[ARP Detector] 🔍 Gratuitous ARP Flood: {len(gratuitous_arps)} packets")
    
    print(f"[ARP Detector] Analysis complete: {len(findings)} findings")
    return findings


def is_likely_gateway(ip):
    """Check if IP is likely a gateway (ends in .1 or .254)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        last_octet = int(str(ip_obj).split('.')[-1])
        return last_octet in [1, 254]
    except:
        return False


def format_duration(seconds):
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    else:
        return f"{int(seconds / 3600)} hours"