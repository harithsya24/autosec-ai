from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

# Initialize the RAG system
rag = ThreatIntelligenceRAG()

# Test threat intelligence retrieval
query = "unauthorized access attempts"
threat_results = rag.search_threats(query)
print(f"Threat search results ({len(threat_results)} found):")
for result in threat_results:
    print(result['metadata'])

# Test CVE retrieval
cve_results = rag.search_cves("remote code execution")
print(f"CVE search results ({len(cve_results)} found):")
for result in cve_results:
    print(result['metadata'])

# Test incident report retrieval
incident_results = rag.search_incidents("phishing attack")
print(f"Incident search results ({len(incident_results)} found):")
for result in incident_results:
    print(result['metadata'])
