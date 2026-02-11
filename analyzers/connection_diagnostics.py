"""
Connection Diagnostics Module
Analyzes traffic for connectivity issues (TCP Resets, Retransmissions, etc.)
"""
from scapy.all import TCP, ICMP, IP

class ConnectionDiagnostics:
    def __init__(self):
        self.diagnostics = {
            'tcp_resets': [],
            'retransmissions': [],
            'icmp_unreachable': [],
            'analysis_summary': []
        }

    def analyze_packets(self, packets):
        """
        Analyze packets for connection issues
        """
        seen_seq = {}  # Track sequence numbers for retransmissions
        
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                # TCP Analysis
                if TCP in pkt:
                    tcp = pkt[TCP]
                    flags = tcp.flags
                    
                    # 1. TCP Reset (RST)
                    if 'R' in flags:
                        self.diagnostics['tcp_resets'].append({
                            'src': src,
                            'dst': dst,
                            'port': tcp.dport,
                            'reason': 'Connection Reset (RST) - Firewall or Service Down'
                        })
                        
                    # 2. Retransmissions (duplicate SEQ)
                    # Simple heuristic: if we see same SEQ from same SRC/DST
                    # Note: This is simplified. Real retransmission detection is complex.
                    # flow_id = f"{src}:{tcp.sport}->{dst}:{tcp.dport}"
                    # if flow_id in seen_seq and seen_seq[flow_id] == tcp.seq:
                    #     self.diagnostics['retransmissions'].append({
                    #          'src': src,
                    #          'dst': dst,
                    #          'seq': tcp.seq
                    #     })
                    # seen_seq[flow_id] = tcp.seq

                # ICMP Analysis
                if ICMP in pkt:
                    # Type 3: Destination Unreachable
                    if pkt[ICMP].type == 3:
                        code = pkt[ICMP].code
                        reason = self._get_icmp_code_desc(code)
                        self.diagnostics['icmp_unreachable'].append({
                            'src': src,
                            'dst': dst,
                            'reason': reason
                        })

        self._generate_summary()
        return self.diagnostics

    def _get_icmp_code_desc(self, code):
        codes = {
            0: "Net Unreachable",
            1: "Host Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed",
            13: "Communication Administratively Prohibited"
        }
        return codes.get(code, f"Unreachable (Code {code})")

    def _generate_summary(self):
        """Generate human-readable remediation steps"""
        rst_count = len(self.diagnostics['tcp_resets'])
        if rst_count > 0:
            self.diagnostics['analysis_summary'].append({
                'issue': f"Detected {rst_count} TCP Resets",
                'severity': 'Medium',
                'remediation': "Check firewall logs. Ensure the destination service is running and listening on the target port."
            })
            
        icmp_count = len(self.diagnostics['icmp_unreachable'])
        if icmp_count > 0:
            self.diagnostics['analysis_summary'].append({
                'issue': f"Detected {icmp_count} ICMP Unreachable messages",
                'severity': 'High',
                'remediation': "Check network routing tables and firewall rules. Verify host availability."
            })

def run_diagnostics(packets):
    diag = ConnectionDiagnostics()
    return diag.analyze_packets(packets)
