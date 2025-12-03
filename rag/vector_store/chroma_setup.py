"""
rag/vector_store/chroma_setup.py
Initialize ChromaDB vector store with threat intelligence
"""
import chromadb
from chromadb.config import Settings
import json
from typing import List, Dict, Any
from datetime import datetime
import os

class ThreatIntelligenceRAG:
    def __init__(self, persist_dir: str = "data/vector_store"):
        """Initialize ChromaDB client and collections"""
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)
        
        self.client = chromadb.PersistentClient(path=persist_dir)
        
        self.threat_collection = self.client.get_or_create_collection(
            name="threat_intelligence",
            metadata={"description": "MITRE ATT&CK techniques and tactics"}
        )
        self.cve_collection = self.client.get_or_create_collection(
            name="cve_database",
            metadata={"description": "CVE vulnerability data"}
        )
        self.incident_collection = self.client.get_or_create_collection(
            name="incident_reports",
            metadata={"description": "Historical incident reports"}
        )
    
    def add_threat_documents(self, documents: List[Dict[str, Any]]):
        """Add MITRE ATT&CK documents to vector store"""
        for doc in documents:
            doc_id = doc.get("id", f"mitre_{datetime.now().timestamp()}")
            
            text_content = f"""
            Title: {doc.get('title', '')}
            Description: {doc.get('description', '')}
            Tactics: {', '.join(doc.get('tactics', []))}
            Indicators: {', '.join(doc.get('indicators', []))}
            Mitigations: {', '.join(doc.get('mitigations', []))}
            """
            
            self.threat_collection.add(
                ids=[doc_id],
                documents=[text_content],
                metadatas=[{
                    "type": "mitre_attack",
                    "title": doc.get("title"),
                    "tactics": ",".join(doc.get("tactics", [])),
                }]
            )
    
    def add_cve_documents(self, documents: List[Dict[str, Any]]):
        """Add CVE documents to vector store"""
        for doc in documents:
            cve_id = doc.get("id", f"cve_{datetime.now().timestamp()}")
            
            text_content = f"""
            CVE ID: {doc.get('cve_id', '')}
            Description: {doc.get('description', '')}
            CVSS Score: {doc.get('cvss_score', '')}
            Affected Software: {doc.get('affected_software', '')}
            Recommendations: {doc.get('recommendations', '')}
            """
            
            self.cve_collection.add(
                ids=[cve_id],
                documents=[text_content],
                metadatas=[{
                    "type": "cve",
                    "cve_id": doc.get("cve_id"),
                    "cvss_score": str(doc.get("cvss_score", ""))
                }]
            )
    
    def add_incident_reports(self, documents: List[Dict[str, Any]]):
        """Add incident report documents"""
        for doc in documents:
            incident_id = doc.get("id", f"incident_{datetime.now().timestamp()}")
            
            text_content = f"""
            Title: {doc.get('title', '')}
            Description: {doc.get('description', '')}
            Attack Vectors: {', '.join(doc.get('attack_vectors', []))}
            Impact: {doc.get('impact', '')}
            Lessons Learned: {doc.get('lessons_learned', '')}
            """
            
            self.incident_collection.add(
                ids=[incident_id],
                documents=[text_content],
                metadatas=[{
                    "type": "incident",
                    "title": doc.get("title"),
                    "date": doc.get("date", "unknown")
                }]
            )
    
    def search_threats(self, query: str, n_results: int = 3) -> List[Dict]:
        """Search threat intelligence"""
        results = self.threat_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        return self._format_results(results)
    
    def search_cves(self, query: str, n_results: int = 3) -> List[Dict]:
        """Search CVE database"""
        results = self.cve_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        return self._format_results(results)
    
    def search_incidents(self, query: str, n_results: int = 3) -> List[Dict]:
        """Search incident reports"""
        results = self.incident_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        return self._format_results(results)
    
    def _format_results(self, results: Dict) -> List[Dict]:
        """Format ChromaDB results"""
        formatted = []
        if not results or not results.get('documents'):
            return formatted
        
        for i, doc in enumerate(results['documents'][0]):
            formatted.append({
                'document': doc,
                'metadata': results['metadatas'][0][i] if results.get('metadatas') else {},
                'distance': results['distances'][0][i] if results.get('distances') else None
            })
        return formatted
    
    def get_collection_stats(self) -> Dict:
        """Get stats on all collections"""
        return {
            'threats': self.threat_collection.count(),
            'cves': self.cve_collection.count(),
            'incidents': self.incident_collection.count()
        }


def create_sample_threat_documents() -> List[Dict]:
    """Create sample MITRE ATT&CK documents"""
    return [
        {
            "id": "MITRE_T1078",
            "title": "Valid Accounts",
            "description": "Attackers may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "tactics": ["initial-access", "persistence", "privilege-escalation"],
            "indicators": ["multiple failed logins", "unusual access patterns", "access from new IPs", "off-hours access"],
            "mitigations": ["MFA enforcement", "rate limiting", "account lockout policies"]
        },
        {
            "id": "MITRE_T1566",
            "title": "Phishing",
            "description": "Attackers may send phishing messages to gain access to victim systems.",
            "tactics": ["initial-access"],
            "indicators": ["suspicious emails", "credential harvesting domains", "malicious attachments"],
            "mitigations": ["security awareness training", "email filtering", "sender authentication"]
        },
        {
            "id": "MITRE_T1059",
            "title": "Command and Scripting Interpreter",
            "description": "Attackers may abuse command and script interpreters to execute commands, scripts, or binaries.",
            "tactics": ["execution"],
            "indicators": ["unusual process execution", "script execution", "command line activity"],
            "mitigations": ["disable unnecessary interpreters", "application whitelisting"]
        }
    ]


def create_sample_cve_documents() -> List[Dict]:
    """Create sample CVE documents"""
    return [
        {
            "id": "cve_2024_001",
            "cve_id": "CVE-2024-1234",
            "description": "Remote Code Execution vulnerability in popular web server",
            "cvss_score": 9.8,
            "affected_software": "WebServer v1.0-2.3",
            "recommendations": "Update to v2.4 or later immediately"
        },
        {
            "id": "cve_2024_002",
            "cve_id": "CVE-2024-5678",
            "description": "SQL Injection in authentication module",
            "cvss_score": 8.6,
            "affected_software": "Database Framework v3.x",
            "recommendations": "Apply security patch or upgrade"
        }
    ]


def create_sample_incident_reports() -> List[Dict]:
    """Create sample incident reports"""
    return [
        {
            "id": "incident_001",
            "title": "Credential Stuffing Attack",
            "description": "Attackers used leaked credentials to gain unauthorized access",
            "attack_vectors": ["valid accounts", "brute force", "credential reuse"],
            "impact": "Data breach affecting 50K users",
            "lessons_learned": "Implement MFA and monitor failed login attempts",
            "date": "2024-01-15"
        },
        {
            "id": "incident_002",
            "title": "Ransomware Deployment",
            "description": "Malware spread through phishing emails and executed ransomware",
            "attack_vectors": ["phishing", "malware", "command execution"],
            "impact": "Systems encrypted, recovery took 48 hours",
            "lessons_learned": "Improve email security and maintain offline backups",
            "date": "2024-02-10"
        }
    ]


if __name__ == "__main__":
    # Initialize RAG system
    rag = ThreatIntelligenceRAG()
    
    threat_docs = create_sample_threat_documents()
    cve_docs = create_sample_cve_documents()
    incident_docs = create_sample_incident_reports()
    
    rag.add_threat_documents(threat_docs)
    rag.add_cve_documents(cve_docs)
    rag.add_incident_reports(incident_docs)
    
    print(" Vector store initialized with sample data")
    print(f"Stats: {rag.get_collection_stats()}")
    
    # Test retrieval
    print("\n Testing retrieval:")
    threat_results = rag.search_threats("login failures and unauthorized access")
    print(f"Threat search results: {len(threat_results)} found")
    for result in threat_results:
        print(f"  - {result['metadata']}")
    
    cve_results = rag.search_cves("remote code execution")
    print(f"CVE search results: {len(cve_results)} found")