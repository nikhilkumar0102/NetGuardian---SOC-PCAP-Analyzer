"""
PCAP File Processing Utilities
Handles loading, parsing, and extracting metadata from PCAP files
"""

from scapy.all import rdpcap, PcapReader
from datetime import datetime
import os

def load_pcap(filepath):
    """
    Load PCAP file and return packets
    
    Args:
        filepath (str): Path to PCAP file
        
    Returns:
        list: List of packets or None if error
    """
    try:
        print(f"[PCAP Processor] Loading PCAP file: {filepath}")
        packets = rdpcap(filepath)
        print(f"[PCAP Processor] Successfully loaded {len(packets)} packets")
        return packets
    except Exception as e:
        print(f"[PCAP Processor] Error loading PCAP: {e}")
        return None


def get_pcap_info(filepath):
    """
    Extract metadata and statistics from PCAP file
    
    Args:
        filepath (str): Path to PCAP file
        
    Returns:
        dict: PCAP metadata including packet count, duration, protocols, etc.
    """
    try:
        packets = rdpcap(filepath)
        
        if not packets:
            return {
                'error': 'No packets found in PCAP file',
                'packet_count': 0
            }
        
        # Basic info
        packet_count = len(packets)
        file_size = os.path.getsize(filepath)
        
        # Time range
        first_packet_time = float(packets[0].time)
        last_packet_time = float(packets[-1].time)
        duration = last_packet_time - first_packet_time
        
        start_time = datetime.fromtimestamp(first_packet_time)
        end_time = datetime.fromtimestamp(last_packet_time)
        
        # Protocol analysis
        protocols = analyze_protocols(packets)
        
        # IP statistics
        ip_stats = analyze_ip_addresses(packets)
        
        info = {
            'packet_count': packet_count,
            'file_size_bytes': file_size,
            'file_size_mb': round(file_size / (1024 * 1024), 2),
            'duration_seconds': round(duration, 2),
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'protocols': protocols,
            'unique_ips': ip_stats['unique_ips'],
            'src_ips': ip_stats['src_ips'],
            'dst_ips': ip_stats['dst_ips']
        }
        
        print(f"[PCAP Processor] PCAP Info:")
        print(f"  - Packets: {packet_count}")
        print(f"  - Duration: {duration:.2f}s")
        print(f"  - Protocols: {', '.join([f'{k}({v})' for k, v in protocols.items()])}")
        
        return info
        
    except Exception as e:
        print(f"[PCAP Processor] Error getting PCAP info: {e}")
        return {
            'error': str(e),
            'packet_count': 0
        }


def analyze_protocols(packets):
    """
    Count packets by protocol type
    
    Args:
        packets (list): List of packets
        
    Returns:
        dict: Protocol counts
    """
    protocols = {
        'TCP': 0,
        'UDP': 0,
        'ICMP': 0,
        'ARP': 0,
        'DNS': 0,
        'HTTP': 0,
        'HTTPS': 0,
        'Other': 0
    }
    
    from scapy.all import TCP, UDP, ICMP, ARP, DNS, IP
    
    for pkt in packets:
        if pkt.haslayer(TCP):
            protocols['TCP'] += 1
            # Check for HTTP/HTTPS
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                protocols['HTTP'] += 1
            elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                protocols['HTTPS'] += 1
        elif pkt.haslayer(UDP):
            protocols['UDP'] += 1
        elif pkt.haslayer(ICMP):
            protocols['ICMP'] += 1
        elif pkt.haslayer(ARP):
            protocols['ARP'] += 1
        
        if pkt.haslayer(DNS):
            protocols['DNS'] += 1
    
    # Remove zero counts
    protocols = {k: v for k, v in protocols.items() if v > 0}
    
    return protocols


def analyze_ip_addresses(packets):
    """
    Extract unique IP addresses from packets
    
    Args:
        packets (list): List of packets
        
    Returns:
        dict: IP address statistics
    """
    from scapy.all import IP
    
    src_ips = set()
    dst_ips = set()
    
    for pkt in packets:
        if pkt.haslayer(IP):
            src_ips.add(pkt[IP].src)
            dst_ips.add(pkt[IP].dst)
    
    all_ips = src_ips.union(dst_ips)
    
    return {
        'unique_ips': len(all_ips),
        'src_ips': len(src_ips),
        'dst_ips': len(dst_ips)
    }


def extract_packet_summary(packet):
    """
    Extract human-readable summary from a packet
    
    Args:
        packet: Scapy packet object
        
    Returns:
        str: Packet summary
    """
    try:
        return packet.summary()
    except:
        return "Unknown packet"


def filter_packets_by_protocol(packets, protocol):
    """
    Filter packets by protocol type
    
    Args:
        packets (list): List of packets
        protocol (str): Protocol name (TCP, UDP, ICMP, ARP, DNS, HTTP)
        
    Returns:
        list: Filtered packets
    """
    from scapy.all import TCP, UDP, ICMP, ARP, DNS
    
    protocol_map = {
        'TCP': TCP,
        'UDP': UDP,
        'ICMP': ICMP,
        'ARP': ARP,
        'DNS': DNS
    }
    
    if protocol not in protocol_map:
        return []
    
    layer = protocol_map[protocol]
    return [pkt for pkt in packets if pkt.haslayer(layer)]


def get_packet_timestamp(packet):
    """
    Get timestamp from packet
    
    Args:
        packet: Scapy packet object
        
    Returns:
        datetime: Packet timestamp
    """
    return datetime.fromtimestamp(float(packet.time))