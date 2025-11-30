#!/usr/bin/env python3
"""
Initialize RAG system with threat intelligence data
Run this script once to populate the vector store
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from rag.vector_store.chroma_setup import (
    ThreatIntelligenceRAG,
    create_sample_threat_documents,
    create_sample_cve_documents,
    create_sample_incident_reports
)


def main():
    """Initialize RAG system with sample data"""
    print(" Initializing AutoSec AI RAG System...")
    print("=" * 60)
    
    # Initialize RAG
    print("\n📚 Creating vector store...")
    rag = ThreatIntelligenceRAG()
    
    # Check current stats
    stats = rag.get_collection_stats()
    print(f"\n Current stats:")
    print(f"  Threats: {stats['threats']}")
    print(f"  CVEs: {stats['cves']}")
    print(f"  Incidents: {stats['incidents']}")
    
    # Load sample data
    if stats['threats'] == 0:
        print("\n Loading sample threat intelligence...")
        threat_docs = create_sample_threat_documents()
        rag.add_threat_documents(threat_docs)
        print(f"   Added {len(threat_docs)} threat documents")
    else:
        print("\n✓ Threat intelligence already loaded")
    
    if stats['cves'] == 0:
        print("\n Loading sample CVE data...")
        cve_docs = create_sample_cve_documents()
        rag.add_cve_documents(cve_docs)
        print(f"   Added {len(cve_docs)} CVE documents")
    else:
        print("\n✓ CVE data already loaded")
    
    if stats['incidents'] == 0:
        print("\n Loading sample incident reports...")
        incident_docs = create_sample_incident_reports()
        rag.add_incident_reports(incident_docs)
        print(f"   Added {len(incident_docs)} incident reports")
    else:
        print("\n✓ Incident reports already loaded")
    
    # Final stats
    final_stats = rag.get_collection_stats()
    print(f"\n RAG System Initialized!")
    print(f"\n Final stats:")
    print(f"  Threats: {final_stats['threats']}")
    print(f"  CVEs: {final_stats['cves']}")
    print(f"  Incidents: {final_stats['incidents']}")
    
    # Test retrieval
    print("\n Testing retrieval...")
    test_query = "multiple failed login attempts"
    results = rag.search_threats(test_query, n_results=2)
    print(f"  Query: '{test_query}'")
    print(f"  Results: {len(results)} found")
    if results:
        print(f"  Top match: {results[0].get('metadata', {}).get('title', 'N/A')}")
    
    print("\n RAG initialization complete!")
    print("\n Next steps:")
    print("  1. Train the Log Analyzer: POST /api/v1/train")
    print("  2. Start the API server: python backend/api/main.py")
    print("  3. Test analysis: POST /api/v1/analyze")


if __name__ == "__main__":
    main()

