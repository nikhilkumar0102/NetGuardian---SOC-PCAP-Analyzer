"""
NetGuardian - SOC PCAP Analysis Tool
Main Flask Application
Author: Nikhil Kumar
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')

app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============================================
# Helper Functions
# ============================================

def allowed_file(filename):
    """Check if uploaded file has valid extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size_mb(filepath):
    """Get file size in MB"""
    size_bytes = os.path.getsize(filepath)
    return round(size_bytes / (1024 * 1024), 2)

# ============================================
# Routes
# ============================================

@app.route('/')
def index():
    """Home page with upload form"""
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle PCAP file upload and trigger analysis"""
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file type. Only .pcap and .pcapng files are allowed'
            }), 400
        
        # Secure the filename
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save the file
        file.save(filepath)
        
        # Get file size
        file_size = get_file_size_mb(filepath)
        
        # Store file info in session for dashboard
        session['uploaded_file'] = {
            'filename': filename,
            'filepath': filepath,
            'size_mb': file_size,
            'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Run PCAP analysis
        analysis_results = analyze_pcap_file(filepath)
        session['analysis_results'] = analysis_results
        
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename,
            'size_mb': file_size,
            'redirect': '/dashboard'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/dashboard')
def dashboard():
    """Display analysis results dashboard"""
    # Check if analysis results exist in session
    if 'analysis_results' not in session:
        return redirect(url_for('index'))
    
    results = session.get('analysis_results')
    file_info = session.get('uploaded_file')
    
    return render_template('dashboard.html', 
                         results=results,
                         file_info=file_info)

@app.route('/report')
def report():
    """Generate detailed analysis report"""
    if 'analysis_results' not in session:
        return redirect(url_for('index'))
    
    results = session.get('analysis_results')
    file_info = session.get('uploaded_file')
    
    return render_template('report.html',
                         results=results,
                         file_info=file_info)

@app.route('/clear')
def clear_session():
    """Clear session and uploaded files"""
    # Delete uploaded file if exists
    if 'uploaded_file' in session:
        filepath = session['uploaded_file'].get('filepath')
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass
    
    # Clear session
    session.clear()
    
    return redirect(url_for('index'))

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# ============================================
# PCAP Analysis Function
# ============================================

def analyze_pcap_file(filepath):
    """
    Perform real analysis on PCAP file
    
    Args:
        filepath (str): Path to PCAP file
        
    Returns:
        dict: Analysis results
    """
    from analyzers.arp_detector import detect_arp_poisoning
    from analyzers.http_parser import extract_http_credentials
    from analyzers.dns_analyzer import detect_dns_exfiltration
    from analyzers.correlator import correlate_events
    from scapy.all import rdpcap
    import time
    
    print("\n" + "="*60)
    print("STARTING PCAP ANALYSIS")
    print("="*60)
    
    start_time = time.time()
    
    try:
        # Load PCAP to get packet count
        packets = rdpcap(filepath)
        total_packets = len(packets)
        print(f"Total packets: {total_packets}")
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        total_packets = 0
    
    # Run analysis modules
    print("\n--- Running Analysis Modules ---")
    arp_findings = detect_arp_poisoning(filepath)
    http_findings = extract_http_credentials(filepath)
    dns_findings = detect_dns_exfiltration(filepath)
    
    # Correlate events
    print("\n--- Correlating Events ---")
    correlation = correlate_events(arp_findings, http_findings, dns_findings)
    
    # Calculate summary statistics
    total_findings = len(arp_findings) + len(http_findings) + len(dns_findings)
    critical_count = len(arp_findings)
    high_count = len(http_findings)
    medium_count = len(dns_findings)
    
    # Calculate risk score (0-10)
    risk_score = min(10, (critical_count * 3 + high_count * 2 + medium_count * 1) / 2)
    
    # Analysis duration
    duration = time.time() - start_time
    
    results = {
        'summary': {
            'total_findings': total_findings,
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': 0,
            'total_packets': total_packets,
            'analysis_duration': f"{duration:.2f} seconds",
            'risk_score': round(risk_score, 1)
        },
        'arp_poisoning': arp_findings,
        'http_credentials': http_findings,
        'dns_exfiltration': dns_findings,
        'timeline': correlation['timeline'],
        'affected_hosts': correlation['affected_hosts']
    }
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"Total Findings: {total_findings}")
    print(f"  - Critical: {critical_count}")
    print(f"  - High: {high_count}")
    print(f"  - Medium: {medium_count}")
    print(f"Risk Score: {risk_score}/10")
    print(f"Duration: {duration:.2f}s")
    print("="*60 + "\n")
    
    return results

# ============================================
# Error Handlers
# ============================================

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({
        'error': 'File too large. Maximum file size is 100MB'
    }), 413

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('upload.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error. Please try again.'
    }), 500

# ============================================
# Main
# ============================================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║              🛡️  NETGUARDIAN  🛡️                         ║
    ║                                                           ║
    ║          SOC Network Analysis Platform                    ║
    ║                    v1.0                                   ║
    ║                                                           ║
    ║  Server starting on: http://localhost:5000                ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Run Flask app
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        threaded=True
    )