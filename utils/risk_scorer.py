"""
Risk Scoring Utilities
Calculates risk scores based on security findings
"""

def calculate_risk_score(findings):
    """
    Calculate overall risk score based on findings
    
    Args:
        findings (dict): Dictionary containing all findings
        
    Returns:
        float: Risk score from 0-10
    """
    # Severity weights
    weights = {
        'CRITICAL': 3.0,
        'HIGH': 2.0,
        'MEDIUM': 1.0,
        'LOW': 0.5
    }
    
    # Count findings by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    # Count from all finding types
    all_findings = []
    
    if 'arp_poisoning' in findings:
        all_findings.extend(findings['arp_poisoning'])
    
    if 'http_credentials' in findings:
        all_findings.extend(findings['http_credentials'])
    
    if 'dns_exfiltration' in findings:
        all_findings.extend(findings['dns_exfiltration'])
    
    # Count by severity
    for finding in all_findings:
        severity = finding.get('severity', 'LOW')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Calculate weighted score
    score = 0
    for severity, count in severity_counts.items():
        score += count * weights[severity]
    
    # Normalize to 0-10 scale
    # Formula: min(10, weighted_sum / 2)
    risk_score = min(10.0, score / 2)
    
    return round(risk_score, 1)


def get_risk_level(risk_score):
    """
    Get risk level description based on score
    
    Args:
        risk_score (float): Risk score from 0-10
        
    Returns:
        str: Risk level description
    """
    if risk_score >= 8.0:
        return "CRITICAL"
    elif risk_score >= 6.0:
        return "HIGH"
    elif risk_score >= 4.0:
        return "MEDIUM"
    elif risk_score >= 2.0:
        return "LOW"
    else:
        return "MINIMAL"


def get_risk_color(risk_score):
    """
    Get color code for risk visualization
    
    Args:
        risk_score (float): Risk score from 0-10
        
    Returns:
        str: CSS color variable
    """
    if risk_score >= 8.0:
        return "var(--accent-danger)"
    elif risk_score >= 6.0:
        return "var(--accent-warning)"
    elif risk_score >= 4.0:
        return "var(--accent-primary)"
    else:
        return "var(--accent-success)"


def calculate_confidence_score(finding):
    """
    Calculate confidence score for a finding
    
    Args:
        finding (dict): Finding dictionary
        
    Returns:
        str: Confidence level (HIGH, MEDIUM, LOW)
    """
    confidence = finding.get('confidence', 'LOW')
    
    # Validate confidence level
    valid_levels = ['HIGH', 'MEDIUM', 'LOW']
    if confidence.upper() not in valid_levels:
        return 'LOW'
    
    return confidence.upper()


def prioritize_findings(findings):
    """
    Prioritize findings by severity and confidence
    
    Args:
        findings (list): List of finding dictionaries
        
    Returns:
        list: Sorted findings (highest priority first)
    """
    severity_order = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1
    }
    
    confidence_order = {
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1
    }
    
    def priority_key(finding):
        severity = finding.get('severity', 'LOW')
        confidence = finding.get('confidence', 'LOW')
        
        severity_score = severity_order.get(severity, 0)
        confidence_score = confidence_order.get(confidence, 0)
        
        # Combined priority: severity * 10 + confidence
        return severity_score * 10 + confidence_score
    
    return sorted(findings, key=priority_key, reverse=True)


def get_remediation_priority(finding):
    """
    Get remediation priority for a finding
    
    Args:
        finding (dict): Finding dictionary
        
    Returns:
        str: Priority level (IMMEDIATE, URGENT, HIGH, MEDIUM, LOW)
    """
    severity = finding.get('severity', 'LOW')
    confidence = finding.get('confidence', 'LOW')
    
    if severity == 'CRITICAL' and confidence == 'HIGH':
        return 'IMMEDIATE'
    elif severity == 'CRITICAL' or (severity == 'HIGH' and confidence == 'HIGH'):
        return 'URGENT'
    elif severity == 'HIGH':
        return 'HIGH'
    elif severity == 'MEDIUM':
        return 'MEDIUM'
    else:
        return 'LOW'