"""
NetGuardian Remote Sensor Agent
-------------------------------
Runs on any device (Windows/Linux/macOS) to capture and stream network traffic 
to the NetGuardian server for analysis.

Requirements:
    pip install scapy requests

Usage:
    python remote_agent.py --server http://<server_ip>:5000 --secret <api_key>
"""

import argparse
import time
import sys
import os
import requests
import queue
import threading
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, conf

# Buffer for packets before sending
PACKET_QUEUE = queue.Queue()
BATCH_SIZE = 50  # Packets per chunk
FLUSH_INTERVAL = 2.0  # Seconds

def packet_callback(pkt):
    """Callback for every captured packet"""
    PACKET_QUEUE.put(pkt)

def uploader_thread(server_url, api_key, interface):
    """Worker thread to upload packets in batches"""
    print(f"[*] Uplink established to {server_url}")
    
    buffer = []
    last_flush = time.time()
    
    while True:
        try:
            # Non-blocking get
            try:
                pkt = PACKET_QUEUE.get(timeout=0.5)
                buffer.append(pkt)
            except queue.Empty:
                pass
            
            # Flush conditions
            current_time = time.time()
            if len(buffer) >= BATCH_SIZE or (len(buffer) > 0 and current_time - last_flush > FLUSH_INTERVAL):
                _send_batch(server_url, api_key, buffer, interface)
                buffer = []
                last_flush = current_time
                
        except Exception as e:
            print(f"[!] Uploader error: {e}")
            time.sleep(2)

def _send_batch(server_url, api_key, packets, interface):
    """Encode and send packet batch"""
    try:
        # Write to temporary pcap bytes
        temp_file = f"temp_{int(time.time()*1000)}.pcap"
        wrpcap(temp_file, packets)
        
        with open(temp_file, 'rb') as f:
            files = {'file': (f'batch_{int(time.time())}.pcap', f, 'application/vnd.tcpdump.pcap')}
            headers = {'X-API-Key': api_key, 'X-Interface': interface}
            
            # Send to server
            r = requests.post(f"{server_url}/api/ingest", files=files, headers=headers, timeout=5)
            
            if r.status_code == 200:
                print(f"[+] Sent {len(packets)} packets. Server: {r.json().get('status')}")
            else:
                print(f"[!] Server rejected batch: {r.status_code} - {r.text}")
                
        os.remove(temp_file)
        
    except Exception as e:
        print(f"[!] Upload failed: {e}")
        # In a real agent, we might retry or buffer to disk

def list_interfaces():
    print("\nAvailable Network Interfaces:")
    for i, iface in enumerate(conf.ifaces):
        print(f"  {i}: {iface.name} ({iface.ip if hasattr(iface, 'ip') else 'No IP'})")
    print("")

def main():
    parser = argparse.ArgumentParser(description='NetGuardian Remote Sensor')
    parser.add_argument('--server', required=True, help='NetGuardian Server URL (e.g., http://192.168.1.100:5000)')
    parser.add_argument('--key', required=True, help='API Key (configured in NetGuardian Settings)')
    parser.add_argument('--iface', help='Interface to capture on (default: auto)')
    parser.add_argument('--list-ifaces', action='store_true', help='List available interfaces and exit')
    
    args = parser.parse_args()
    
    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)
        
    print(f"""
    ╔══════════════════════════════════════════╗
    ║      NetGuardian Remote Sensor v1.0      ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Start Uploader
    t = threading.Thread(target=uploader_thread, args=(args.server, args.key, args.iface or "default"), daemon=True)
    t.start()
    
    # Start Capture
    print(f"[*] Starting capture on {args.iface or 'default interface'}...")
    try:
        if args.iface:
            sniff(iface=args.iface, prn=packet_callback, store=0)
        else:
            sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
    except Exception as e:
        print(f"\n[!] Capture error: {e}")
        if "libpcap" in str(e).lower() or "npcap" in str(e).lower():
            print("HINT: Ensure Npcap (Windows) or libpcap (Linux) is installed.")

if __name__ == "__main__":
    main()
