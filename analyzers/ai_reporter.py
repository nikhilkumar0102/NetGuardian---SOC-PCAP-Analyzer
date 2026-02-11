"""
AI Reporter Module
Generates narrative analysis using LLMs (Gemini/OpenAI)
"""

import requests
import json
import os

class AIReporter:
    def __init__(self, api_key=None, provider='gemini'):
        self.api_key = api_key or os.environ.get('AI_API_KEY')
        self.provider = provider

    def generate_report(self, findings_summary):
        """
        Generate a comprehensive security report based on findings.
        """
        if not self.api_key:
            return self._generate_fallback_report(findings_summary)

        try:
            if self.provider == 'gemini':
                return self._call_gemini(findings_summary)
            elif self.provider == 'openai':
                return self._call_openai(findings_summary)
            else:
                return "Unsupported AI Provider"
        except Exception as e:
            print(f"[AIReporter] Error: {e}")
            return self._generate_fallback_report(findings_summary, error=str(e))

    def _call_gemini(self, summary):
        """Call Google Gemini API"""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.api_key}"
        headers = {'Content-Type': 'application/json'}
        
        prompt = self._construct_prompt(summary)
        
        data = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            result = response.json()
            try:
                return result['candidates'][0]['content']['parts'][0]['text']
            except (KeyError, IndexError):
                return "Error parsing AI response."
        else:
            return f"AI API Error: {response.status_code} - {response.text}"

    def _call_openai(self, summary):
        """Call OpenAI API"""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        prompt = self._construct_prompt(summary)
        
        data = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a Senior SOC Analyst. Analyze the network traffic findings and generate a professional security report."},
                {"role": "user", "content": prompt}
            ]
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            return f"AI API Error: {response.status_code}"

    def _construct_prompt(self, summary):
        return f"""
        Analyze the following network security findings from a PCAP file:
        
        {json.dumps(summary, indent=2)}
        
        Please provide a professional report in Markdown format with the following sections:
        1. **Executive Summary**: High-level overview of the threats and risk level.
        2. **Technical Deep Dive**: Analysis of specific attacks (ARP Spoofing, Credential Theft, etc.). Explain WHAT happened and WHY it matters.
        3. **MITRE ATT&CK Mapping**: How these attacks map to the framework.
        4. **Strategic Recommendations**: Actionable steps to mitigate these threats (referencing MITRE D3FEND if possible).
        
        Tone: Professional, Technical, Action-Oriented.
        """

    def _generate_fallback_report(self, summary, error=None):
        """Generate a basic report if AI is unavailable"""
        report = "# Automated Security Analysis (Offline Mode)\n\n"
        
        if error:
            report += f"> **Note**: AI Analysis unavailable ({error}). Showing template report.\n\n"
        else:
            report += "> **Note**: Configure AI API Key in Settings for enhanced analysis.\n\n"
            
        report += "## Executive Summary\n"
        report += f"NetGuardian analyzed the traffic and detected **{summary.get('total_findings', 0)}** potential threats. "
        report += f"The overall risk score is **{summary.get('risk_score', 0)}/10**.\n\n"
        
        report += "## Detected Threats\n"
        if summary.get('arp_poisoning'):
            report += f"- **ARP Poisoning**: {len(summary['arp_poisoning'])} incidents detected. Indicates potential MITM attacks.\n"
        if summary.get('http_credentials'):
            report += f"- **Credential Theft**: {len(summary['http_credentials'])} plaintext credentials captured.\n"
            
        report += "\n## Recommendations\n"
        report += "- **Immediate Action**: Isolate affected hosts.\n"
        report += "- **Mitigation**: Enable DAI and enforce HTTPS.\n"
        
        return report
