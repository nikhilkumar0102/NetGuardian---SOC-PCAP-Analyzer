"""
Snort Log Manager and Parser
"""
import os
import re
import subprocess
from datetime import datetime

class SnortManager:
    def __init__(self, snort_bin_path=None):
        self.snort_bin = snort_bin_path or self._find_snort()
        
    def _find_snort(self):
        """Try to locate snort binary in common paths"""
        # This is a basic check. In reality, user might need to configure this.
        common_paths = [
            r"C:\Snort\bin\snort.exe",
            r"C:\Program Files\Snort\bin\snort.exe",
            "/usr/bin/snort",
            "/usr/local/bin/snort"
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None

    def parse_alert_log(self, log_path):
        """
        Parse Snort alert file (fast or full mode).
        Returns list of alerts.
        """
        alerts = []
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    alert = self._parse_line(line)
                    if alert:
                        alerts.append(alert)
        except Exception as e:
            print(f"Error parsing Snort log: {e}")
            
        return alerts

    def _parse_line(self, line):
        """
        Parse a single line of Snort fast alert log
        Format: [**] [sid:rev] Msg [**] [Classification: class] [Priority: prio] {Proto} SrcIP:Port -> DstIP:Port
        """
        # Regex for Snort Fast Alert
        # Example: 10/11-14:30:10.123456  [**] [1:1000001:1] TEST ALERT [**] [Classification: test] [Priority: 1] {TCP} 192.168.1.1:1234 -> 192.168.1.2:80
        regex = r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)?\s*\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.+?)\s*\[\*\*\]\s*(?:\[Classification:\s*(.+?)\])?\s*(?:\[Priority:\s*(\d+)\])?\s*\{(.*?)\}\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?\s*->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?"
        
        match = re.search(regex, line)
        if match:
            # Clean up message
            msg = match.group(5).strip()
            
            return {
                'timestamp': match.group(1),
                'sid': match.group(3),
                'msg': msg,
                'classification': match.group(6) or "Unknown",
                'priority': match.group(7),
                'protocol': match.group(8),
                'src_ip': match.group(9),
                'src_port': match.group(10),
                'dst_ip': match.group(11),
                'dst_port': match.group(12)
            }
        return None

    def run_snort(self, pcap_path, config_path=None, output_dir=None):
        """
        Run Snort on a PCAP file if binary is available
        """
        if not self.snort_bin:
            return {"error": "Snort binary not found"}
            
        # Simplified command construction
        # snort -r <pcap> -l <log_dir> -c <conf> -A fast
        # Note: Requires valid config file.
        pass
