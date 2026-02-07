# 🛡️ NetGuardian - SOC PCAP Analyzer

<div align="center">

![NetGuardian Banner](https://img.shields.io/badge/Security-Network%20Analysis-00f0ff?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-green?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

**Advanced Network Security Analysis Platform for SOC Analysts & Incident Responders**

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

</div>

---

## 📋 Overview

NetGuardian is a powerful, web-based PCAP analysis tool designed for Security Operations Center (SOC) analysts and incident responders. It automatically detects and analyzes network security threats including ARP poisoning attacks, credential exposure, and DNS exfiltration patterns.

### 🎯 Key Capabilities

- **ARP Poisoning Detection** - Identifies Man-in-the-Middle (MITM) attacks via ARP spoofing
- **Credential Exposure Analysis** - Extracts plaintext HTTP credentials and API keys
- **DNS Exfiltration Detection** - Identifies DNS tunneling patterns and suspicious queries
- **MITRE ATT&CK Mapping** - Maps detected threats to MITRE ATT&CK framework
- **Interactive Dashboard** - Beautiful cyberpunk-themed UI with real-time analysis
- **Comprehensive Reporting** - Generates detailed security reports with remediation steps

---

## ✨ Features

### 🔍 Threat Detection

| Attack Type | Detection Method | MITRE ATT&CK |
|-------------|------------------|--------------|
| **ARP Poisoning** | MAC address conflict detection | T1557.002 |
| **HTTP Credentials** | Plaintext credential extraction | T1040 |
| **DNS Exfiltration** | Pattern analysis (hex/base64 encoding) | T1048.003 |

### 🎨 User Interface

- **Cyberpunk Dark Theme** - Eye-catching neon gradients with excellent contrast
- **Collapsible Sections** - Auto-expand/collapse for better UX
- **Real-time Statistics** - Animated counters and live threat indicators
- **Responsive Design** - Works on desktop, tablet, and mobile
- **Accessibility** - WCAG AA compliant contrast ratios

### 📊 Analysis Features

- Timeline visualization of attack events
- Affected hosts identification
- Risk score calculation (0-10 scale)
- Severity classification (Critical, High, Medium, Low)
- Packet-level inspection details
- Export reports in multiple formats

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netguardian-soc-analyzer.git
cd netguardian-soc-analyzer

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

# Access the web interface at http://localhost:5000
```

---

## 📁 Project Structure

```
netguardian-soc-analyzer/
├── app.py                      # Flask application
├── analyzer/
│   ├── arp_detector.py        # ARP poisoning detection
│   ├── credential_extractor.py # HTTP credential analysis
│   └── dns_analyzer.py        # DNS exfiltration detection
├── templates/
│   ├── base.html              # Base template
│   ├── dashboard.html         # Analysis dashboard
│   ├── report.html            # Report view
│   └── upload.html            # Upload interface
├── static/
│   ├── css/
│   │   └── custom.css         # Enhanced cyberpunk theme
│   └── js/
│       └── main.js            # Frontend interactions
├── samples/
│   └── attack_samples.pcap    # Sample PCAP file
└── requirements.txt           # Python dependencies
```

---

## 🔧 Usage

1. **Upload PCAP File** - Drag & drop or browse to select `.pcap` or `.pcapng` file
2. **View Analysis** - Automatic threat detection with interactive dashboard
3. **Generate Report** - Export detailed findings as PDF or HTML
4. **Investigate** - Review MITRE ATT&CK mappings and remediation steps

---

## 🎓 Sample Analysis

The included `attack_samples.pcap` demonstrates detection of:

- **ARP Poisoning** - MITM attack with MAC address spoofing
- **Credential Theft** - Plaintext HTTP POST with username/password
- **DNS Tunneling** - Hex-encoded data exfiltration via DNS queries

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with Flask, Bootstrap, and modern web technologies
- Sample attack patterns based on MITRE ATT&CK framework
- UI design influenced by cyberpunk aesthetics
- Special thanks to the open-source security community

---

<div align="center">

**Made with ❤️ by SOC Analysts, for SOC Analysts**

⭐ Star this repo if you find it useful!

</div>
