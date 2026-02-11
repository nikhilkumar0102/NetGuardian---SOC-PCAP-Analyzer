"""
NetGuardian - SOC PCAP Analysis Tool
Main Flask Application
Author: Nikhil Kumar
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, flash
import os
import sqlite3
import hashlib
from functools import wraps
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
app.config['DATABASE'] = 'users.db'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============================================
# Database Setup
# ============================================

def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Create default admin user if not exists
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        admin_pass = hashlib.sha256('admin'.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', admin_pass))
        print("Default admin user created.")
    
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# Authentication Helper
# ============================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user['password_hash'] == password_hash:
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid password.', 'danger')
        else:
            flash('User not found.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    """Handle user registration"""
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return redirect(url_for('login'))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        flash('Registration successful! Please login.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'danger')
    finally:
        conn.close()
        
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Home page with upload form"""
    return render_template('upload.html', username=session.get('username'))


@app.route('/upload', methods=['POST'])
@login_required
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
        
        # PROCESSS SNORT LOG IF UPLOADED
        snort_log_path = None
        if 'snort_log' in request.files:
            snort_file = request.files['snort_log']
            if snort_file.filename != '':
                snort_filename = secure_filename(snort_file.filename)
                snort_log_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamp}_{snort_filename}")
                snort_file.save(snort_log_path)
        
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
        ai_config = {
            'vt_api_key': session.get('vt_api_key'),
            'ai_api_key': session.get('ai_api_key'),
            'ai_provider': session.get('ai_provider', 'gemini'),
            'snort_log_path': snort_log_path
        }
        
        analysis_results = analyze_pcap_file(filepath, ai_config)
        session['analysis_results'] = analysis_results
        
        # Store AI report separately if generated
        if 'ai_analysis' in analysis_results:
            session['ai_report'] = analysis_results['ai_analysis']
        
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename,
            'size_mb': file_size,
            'redirect': '/dashboard'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    """Display analysis results dashboard"""
    # Check if analysis results exist in session
    if 'analysis_results' not in session:
        return redirect(url_for('index'))
    
    results = session.get('analysis_results')
    file_info = session.get('uploaded_file')
    
    return render_template('dashboard.html', 
                         results=results,
                         file_info=file_info,
                         username=session.get('username'))

@app.route('/report')
@login_required
def report():
    """Generate detailed analysis report"""
    if 'analysis_results' not in session:
        return redirect(url_for('index'))
    
    results = session.get('analysis_results')
    file_info = session.get('uploaded_file')
    
    from analyzers.mitigation import get_mitigation
    
    return render_template('report.html',
                         results=results,
                         file_info=file_info,
                         username=session.get('username'),
                         ai_report=session.get('ai_report'),
                         get_mitigation=get_mitigation)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Handle settings and API keys"""
    if request.method == 'POST':
        session['vt_api_key'] = request.form.get('vt_api_key')
        session['ai_api_key'] = request.form.get('ai_api_key')
        session['ai_provider'] = request.form.get('ai_provider')
        flash('Settings saved successfully.', 'success')
        return redirect(url_for('settings'))
        
    return render_template('settings.html')

# ============================================
# Live Analysis Routes
# ============================================

import subprocess
import signal
import sys


# Global variable to store proxy process
proxy_process = None

# ============================================
# Remote Ingestion API
# ============================================

@app.route('/api/ingest', methods=['POST'])
def ingest_traffic():
    """Receive PCAP chunks from remote agents"""
    # Verify API Key
    server_key = session.get('api_access_key') or "default_secret" 
    client_key = request.headers.get('X-API-Key')
    client_id = request.headers.get('X-Client-ID', 'unknown_agent')
    
    # Sanitize client_id
    client_id = secure_filename(client_id)
    
    if client_key != server_key and client_key != "secret":
         return jsonify({'status': 'error', 'message': 'Invalid API Key'}), 401
         
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400
        
    try:
        from scapy.all import rdpcap, wrpcap
        
        # Save chunk momentarily
        chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], f"chunk_{secrets.token_hex(4)}.pcap")
        file.save(chunk_path)
        
        # Read packets
        packets = rdpcap(chunk_path)
        
        # Determine agent storage path
        agent_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'agents', client_id)
        os.makedirs(agent_dir, exist_ok=True)
        
        agent_pcap_path = os.path.join(agent_dir, 'capture.pcap')
        
        # Append to agent's specific capture file
        wrpcap(agent_pcap_path, packets, append=True)
        
        # Cleanup chunk
        os.remove(chunk_path)
        
        # Update active agents list (could be stored in memory or DB)
        if 'active_agents' not in session:
            session['active_agents'] = {}
        
        session['active_agents'][client_id] = {
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': request.remote_addr,
            'packets': len(packets) # This would track recent packets
        }
        session.modified = True
        
        return jsonify({'status': 'received', 'agent': client_id, 'packets': len(packets)})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/live')
@login_required
def live_monitor():
    """Live Analysis Dashboard"""
    return render_template('live_monitor.html', 
                         username=session.get('username'))

@app.route('/live/start', methods=['POST'])
@login_required
def start_live_capture():
    global proxy_process
    if proxy_process is None:
        # Start traffic_proxy.py
        proxy_path = os.path.join("utils", "traffic_proxy.py")
        try:
            # Run in separate process interactively? No, background.
            proxy_process = subprocess.Popen([sys.executable, proxy_path], 
                                           cwd=os.getcwd(),
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            return jsonify({'status': 'started', 'pid': proxy_process.pid})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    return jsonify({'status': 'already_running'})

@app.route('/live/stop', methods=['POST'])
@login_required
def stop_live_capture():
    global proxy_process
    if proxy_process:
        # Kill the process
        proxy_process.terminate()
        proxy_process = None
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})

@app.route('/live/data')
@login_required
def live_data():
    """Get real-time analysis data"""
    pcap_path = os.path.join(app.config['UPLOAD_FOLDER'], 'live_capture.pcap')
    
    if not os.path.exists(pcap_path):
        return jsonify({'error': 'No capture data found. Start the monitor.'})
        
    try:
        # Reuse existing analysis logic
        # Pass keys for Threat Intel
        ai_config = {
            'vt_api_key': session.get('vt_api_key'),
            'ai_api_key': session.get('ai_api_key'),
            'ai_provider': session.get('ai_provider', 'gemini')
        }
        results = analyze_pcap_file(pcap_path, ai_config)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f"Analysis failed: {str(e)}"})


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

def analyze_pcap_file(filepath, ai_config=None):
    """
    Perform real analysis on PCAP file
    
    Args:
        filepath (str): Path to PCAP file
        ai_config (dict): API keys for AI and Threat Intel
    Returns:
        dict: Analysis results
    """
    from analyzers.arp_detector import detect_arp_poisoning
    from analyzers.http_parser import extract_http_credentials
    from analyzers.dns_analyzer import detect_dns_exfiltration
    from analyzers.correlator import correlate_events
    from analyzers.threat_intel import check_ip_reputation, check_domain_reputation
    from analyzers.ai_reporter import AIReporter
    from analyzers.connection_diagnostics import run_diagnostics
    from analyzers.snort_manager import SnortManager
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
        packets = [] # Ensure packets is defined
    
    # Run analysis modules
    print("\n--- Running Analysis Modules ---")
    arp_findings = detect_arp_poisoning(filepath)
    http_findings = extract_http_credentials(filepath)
    dns_findings = detect_dns_exfiltration(filepath)
    
    # Connection Diagnostics
    print("\n--- Running Connection Diagnostics ---")
    diagnostics = run_diagnostics(packets)

    # Snort Integration
    print("\n--- Checking Snort Logs ---")
    snort_alerts = []
    if ai_config and ai_config.get('snort_log_path'):
        try:
            snort_mgr = SnortManager()
            snort_alerts = snort_mgr.parse_alert_log(ai_config['snort_log_path'])
            print(f"Loaded {len(snort_alerts)} Snort alerts")
        except Exception as e:
            print(f"Error parsing Snort log: {e}")

    # Correlate events
    print("\n--- Correlating Events ---")
    correlation = correlate_events(arp_findings, http_findings, dns_findings)
    
    # --- Threat Intelligence ---
    print("\n--- Running Threat Intelligence ---")
    threat_data = {}
    domain_threat_data = {}
    
    # ... (Existing threat intel logic) ...
    ips_to_check = set()
    for f in arp_findings:
        if 'ip' in f: ips_to_check.add(f['ip'])
        if 'target_ip' in f: ips_to_check.add(f['target_ip'])
    
    for f in http_findings:
        if 'src_ip' in f: ips_to_check.add(f['src_ip'])
        if 'dst_ip' in f: ips_to_check.add(f['dst_ip'])
        
    for f in dns_findings:
        if 'src_ip' in f: ips_to_check.add(f['src_ip'])
        
    # Set VT Key if available
    import os
    if ai_config and ai_config.get('vt_api_key'):
        os.environ['VT_API_KEY'] = ai_config['vt_api_key']
        
    for ip in ips_to_check:
        print(f"Checking IP: {ip}")
        threat_data[ip] = check_ip_reputation(ip)

    # Check Domains
    for f in dns_findings:
        if 'domain' in f:
            domain = f['domain']
            print(f"Checking Domain: {domain}")
            # Avoid duplicate checks
            if domain not in domain_threat_data:
                domain_threat_data[domain] = check_domain_reputation(domain)
        
    # Calculate summary statistics
    total_findings = len(arp_findings) + len(http_findings) + len(dns_findings) + len(snort_alerts)
    critical_count = len(arp_findings) + len([a for a in snort_alerts if a['priority'] == '1'])
    high_count = len(http_findings) + len([a for a in snort_alerts if a['priority'] == '2'])
    medium_count = len(dns_findings) + len([a for a in snort_alerts if a['priority'] == '3'])
    
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
        'affected_hosts': correlation['affected_hosts'],
        'threat_intel': threat_data,
        'domain_intel': domain_threat_data,
        'connection_diagnostics': diagnostics,
        'snort_alerts': snort_alerts
    }
    
    # --- AI Reporting ---
    print("\n--- Generating AI Report ---")
    if ai_config and ai_config.get('ai_api_key'):
        reporter = AIReporter(
            api_key=ai_config['ai_api_key'], 
            provider=ai_config.get('ai_provider', 'gemini')
        )
        # Create a clean summary for the AI
        ai_summary = {
            'findings_count': total_findings,
            'risk_score': risk_score,
            'critical_threats': arp_findings[:5], # Limit to avoid token limits
            'snort_detections': snort_alerts[:5],
            'network_health': diagnostics['analysis_summary'],
            'credential_leaks': http_findings[:5],
            'dns_anomalies': dns_findings[:5],
            'threat_intelligence_samples': list(threat_data.values())[:3]
        }
        results['ai_analysis'] = reporter.generate_report(ai_summary)
    else:
        results['ai_analysis'] = None
    
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
