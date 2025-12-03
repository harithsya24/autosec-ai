#!/usr/bin/env python3
"""
Quick System Test Script
Tests the complete agent pipeline end-to-end
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def test_rag_system():
    """Test RAG system initialization"""
    print("Testing RAG System...")
    try:
        from rag.vector_store.chroma_setup import ThreatIntelligenceRAG
        
        rag = ThreatIntelligenceRAG()
        stats = rag.get_collection_stats()
        
        if stats['threats'] == 0:
            print("    RAG not initialized. Run: python scripts/initialize_rag.py")
            return False
        
        print(f"   Threats: {stats['threats']}")
        print(f"   CVEs: {stats['cves']}")
        print(f"   Incidents: {stats['incidents']}")
        return True
    except Exception as e:
        print(f"   Error: {e}")
        return False

def test_agents():
    """Test individual agents"""
    print("\n Testing Agents...")
    
    results = {}
    
    # Test Threat Intelligence Agent
    try:
        from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
        from rag.vector_store.chroma_setup import ThreatIntelligenceRAG
        
        rag = ThreatIntelligenceRAG()
        agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)
        
        sample_anomaly = {
            "action": "login",
            "status": "failed",
            "severity": "high",
            "anomaly_score": -0.75,
            "features": {"failed_action": True}
        }
        
        analysis = agent.analyze_threat(sample_anomaly)
        results['threat_intel'] = analysis.get('confidence', 0) > 0
        print(f"   Threat Intelligence Agent: {analysis.get('threat_type', 'unknown')}")
    except Exception as e:
        print(f"   Threat Intelligence Agent: {e}")
        results['threat_intel'] = False
    
    # Test Response Agent
    try:
        from backend.agents.response_agent import ResponseAgent
        
        agent = ResponseAgent(sandbox_mode=True)
        threat_analysis = {
            "threat_type": "credential_stuffing",
            "confidence": 0.85,
            "severity": "high"
        }
        anomaly = {"source_ip": "203.45.67.89", "user_id": "user_123"}
        
        recommendations = agent.recommend_actions(threat_analysis, anomaly)
        results['response'] = recommendations['summary']['total_actions'] > 0
        print(f"   Response Agent: {recommendations['summary']['total_actions']} actions recommended")
    except Exception as e:
        print(f"   Response Agent: {e}")
        results['response'] = False
    
    return all(results.values())

def test_orchestrator():
    """Test orchestrator (requires trained model)"""
    print("\nTesting Orchestrator...")
    
    try:
        from backend.agents.orchestrator import OrchestratorAgent
        
        orchestrator = OrchestratorAgent(sandbox_mode=True)
        status = orchestrator.get_system_status()
        
        if not status['log_analyzer']['trained']:
            print("    Log Analyzer not trained. Run: POST /api/v1/train")
            return False
        
        print(f"   Log Analyzer: Trained")
        print(f"   Threat Intel: RAG={'YES' if status['threat_intelligence']['rag_available'] else 'NO'}, "
              f"LLM={'YES' if status['threat_intelligence']['llm_enabled'] else 'NO'}")
        print(f"   Response Agent: Sandbox mode")
        return True
    except Exception as e:
        print(f"   Error: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints (if server is running)"""
    print("\n Testing API Endpoints...")
    
    try:
        import requests
        
        base_url = "http://localhost:8000"
        
        # Health check
        try:
            response = requests.get(f"{base_url}/health", timeout=2)
            if response.status_code == 200:
                print("   Health endpoint: OK")
            else:
                print(f"    Health endpoint: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("    API server not running. Start with: python backend/api/main.py")
            return False
        
        # System status
        try:
            response = requests.get(f"{base_url}/api/v1/system/status", timeout=2)
            if response.status_code == 200:
                print("   System status endpoint: OK")
                return True
            else:
                print(f"    System status: {response.status_code}")
                return False
        except Exception as e:
            print(f"    System status: {e}")
            return False
            
    except ImportError:
        print("    'requests' not installed. Install with: pip install requests")
        return False

def main():
    """Run all tests"""
    print(" AutoSec AI - System Test")
    
    results = {
        "RAG System": test_rag_system(),
        "Agents": test_agents(),
        "Orchestrator": test_orchestrator(),
        "API Endpoints": test_api_endpoints()
    }
    
    print(" Test Results:")
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL / SKIP"
        print(f"  {test_name}: {status}")
    
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    print(f"\n {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n System is ready!")
    else:
        print("\n Next Steps:")
        if not results["RAG System"]:
            print("  1. Initialize RAG: python scripts/initialize_rag.py")
        if not results["Orchestrator"]:
            print("  2. Train Log Analyzer: POST /api/v1/train")
        if not results["API Endpoints"]:
            print("  3. Start API server: python backend/api/main.py")

if __name__ == "__main__":
    main()

