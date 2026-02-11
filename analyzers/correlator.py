"""
Event Correlation Engine
Correlates related security events into attack chains
"""

from datetime import datetime, timedelta

def correlate_events(arp_findings, http_findings, dns_findings):
    """
    Correlate security events to build attack timeline
    
    Args:
        arp_findings (list): ARP poisoning incidents
        http_findings (list): HTTP credential exposures
        dns_findings (list): DNS exfiltration incidents
        
    Returns:
        dict: Correlated timeline and affected hosts
    """
    print("[Correlator] Correlating security events...")
    
    timeline = []
    affected_hosts = {}
    
    # Add ARP events to timeline
    for finding in arp_findings:
        timeline.append({
            'time': finding['timestamp'].split()[1] if ' ' in finding['timestamp'] else finding['timestamp'],
            'event': f"ARP Poisoning detected ({finding['ip']})",
            'severity': finding['severity']
        })
        
        # Track affected host
        ip = finding['ip']
        if ip not in affected_hosts:
            affected_hosts[ip] = {'threats': 0, 'risk': 'LOW'}
        affected_hosts[ip]['threats'] += 1
        affected_hosts[ip]['risk'] = 'CRITICAL'
    
    # Add HTTP events to timeline
    for finding in http_findings:
        username = finding.get('username', 'credentials')
        timeline.append({
            'time': finding['timestamp'].split()[1] if ' ' in finding['timestamp'] else finding['timestamp'],
            'event': f"HTTP Credentials captured ({username})",
            'severity': finding['severity']
        })
        
        # Track affected host
        ip = finding['source_ip']
        if ip not in affected_hosts:
            affected_hosts[ip] = {'threats': 0, 'risk': 'LOW'}
        affected_hosts[ip]['threats'] += 1
        if affected_hosts[ip]['risk'] != 'CRITICAL':
            affected_hosts[ip]['risk'] = 'HIGH'
    
    # Add DNS events to timeline
    for finding in dns_findings:
        timeline.append({
            'time': finding['timestamp'].split()[1] if ' ' in finding['timestamp'] else finding['timestamp'],
            'event': f"DNS Exfiltration to {finding['domain'].split('.')[0]}...",
            'severity': finding['severity']
        })
    
    # Sort timeline by time
    timeline.sort(key=lambda x: x['time'])
    
    # Format affected hosts
    affected_hosts_list = [
        {
            'ip': ip,
            'threats': info['threats'],
            'risk': info['risk']
        }
        for ip, info in affected_hosts.items()
    ]
    
    # Sort by number of threats
    affected_hosts_list.sort(key=lambda x: x['threats'], reverse=True)
    
    print(f"[Correlator] Created timeline with {len(timeline)} events")
    print(f"[Correlator] Identified {len(affected_hosts_list)} affected hosts")
    
    return {
        'timeline': timeline,
        'affected_hosts': affected_hosts_list
    }
