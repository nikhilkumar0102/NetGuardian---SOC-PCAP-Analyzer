"""
MITRE ATT&CK Framework Mapper
Maps detected threats to MITRE ATT&CK techniques
"""

MITRE_TECHNIQUES = {
    'T1557.002': {
        'name': 'Adversary-in-the-Middle: ARP Cache Poisoning',
        'tactic': 'Credential Access, Collection',
        'description': 'Adversaries may poison ARP caches to position themselves between two or more networked devices.'
    },
    'T1040': {
        'name': 'Network Sniffing',
        'tactic': 'Credential Access, Discovery',
        'description': 'Adversaries may sniff network traffic to capture information about an environment.'
    },
    'T1048.003': {
        'name': 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol',
        'tactic': 'Exfiltration',
        'description': 'Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.'
    }
}

def get_technique_info(technique_id):
    """Get MITRE ATT&CK technique information"""
    return MITRE_TECHNIQUES.get(technique_id, {
        'name': 'Unknown Technique',
        'tactic': 'Unknown',
        'description': 'No description available'
    })