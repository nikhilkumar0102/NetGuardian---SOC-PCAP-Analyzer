"""
RAG Engine for MITRE ATT&CK
"""

import json
import os
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

class MitreRAG:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)
        self.techniques = []
        self.embeddings = None
        # Load or initialize MITRE data
        self._load_mitre_data()

    def _load_mitre_data(self):
        """
        Load MITRE ATT&CK data. 
        In a real scenario, this would load from a STIX file or a curated JSON.
        Here we'll use a curated list for demonstration.
        """
        # Dictionary of Technique ID -> Info
        self.techniques = [
            {
                "id": "T1557",
                "name": "Adversary-in-the-Middle",
                "description": "Adversaries may attempt to position themselves between two or more networked devices using ARP Spoofing to support follow-on behaviors such as network sniffing or transmutation of data.",
                "tactic": "Credential Access, Collection"
            },
           {
                "id": "T1040",
                "name": "Network Sniffing",
                "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.",
                "tactic": "Credential Access, Discovery"
            },
            {
                "id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "description": "Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.",
                "tactic": "Exfiltration"
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                "tactic": "Command and Control"
            },
            {
                "id": "T1003",
                "name": "OS Credential Dumping",
                "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.",
                "tactic": "Credential Access"
            },
             {
                "id": "T1110",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "tactic": "Credential Access"
            },
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.",
                "tactic": "Impact"
            },
            {
                "id": "T1595",
                "name": "Active Scanning",
                "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
                "tactic": "Reconnaissance"
            }
        ]
        
        # Pre-compute embeddings
        texts = [f"{t['name']}: {t['description']}" for t in self.techniques]
        self.embeddings = self.model.encode(texts)

    def query(self, text, top_k=3):
        """
        Query the RAG engine for relevant MITRE techniques.
        """
        if not text:
            return []
            
        # create embedding for query
        query_embedding = self.model.encode([text])
        
        # calculate cosine similarity
        similarities = cosine_similarity(query_embedding, self.embeddings)[0]
        
        # get top k indices
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            score = similarities[idx]
            if score > 0.3: # Threshold
                technique = self.techniques[idx].copy()
                technique['score'] = float(score)
                results.append(technique)
                
        return results

if __name__ == "__main__":
    # Simple test
    rag = MitreRAG()
    results = rag.query("Attacker is sniffing traffic to get passwords")
    print(json.dumps(results, indent=2))
