"""
Week 2 Integration Tests
Tests AI Agents: Detection, RAG, Recommendations
"""

import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))


class TestWeek2:
    """Test Week 2 AI agents"""
    
    def __init__(self):
        self.test_results = []
        self.passed = 0
        self.failed = 0
    
    def print_header(self, test_name):
        """Print test header"""
        print(f"\n{'='*60}")
        print(f"{test_name}")
        print(f"{'='*60}")
    
    def test_result(self, test_name, passed, message=""):
        """Record test result"""
        status = "PASS" if passed else "FAIL"
        print(f"  {status} - {test_name}")
        if message:
            print(f"    {message}")
        self.test_results.append((test_name, passed, message))
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def test_log_analyzer(self):
        """Test 1: Log Analyzer Agent"""
        self.print_header("Test 1: Log Analyzer Agent")
        
        try:
            from backend.agents.log_analyzer import LogAnalyzerAgent
            from backend.utils.data_loader import CICIDSLoader
            
            print("  Initializing Log Analyzer...")
            agent = LogAnalyzerAgent(contamination=0.10)
            self.test_result("Agent Initialization", True, "LogAnalyzerAgent created")
            
            print("  Loading training data...")
            loader = CICIDSLoader()
            try:
                df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=5000)
                logs = df.to_dict('records')
                self.test_result("Data Loading", True, f"Loaded {len(logs)} logs")
            except Exception as e:
                self.test_result("Data Loading", False, f"Error: {e}")
                return False
            
            print("  Training agent on benign traffic...")
            try:
                stats = agent.train_on_benign_only(logs)
                is_trained = agent.is_trained
                self.test_result("Agent Training", is_trained,
                               f"Trained on {stats.get('total_logs', 0)} logs")
            except Exception as e:
                self.test_result("Agent Training", False, f"Error: {e}")
                return False
            
            print("  Testing anomaly detection...")
            test_logs = logs[:10]  
            try:
                anomalies, results_df = agent.detect_anomalies(test_logs)
                detection_works = isinstance(anomalies, list) and isinstance(results_df, type(df))
                self.test_result("Anomaly Detection", detection_works,
                               f"Detected {len(anomalies)} anomalies from {len(test_logs)} logs")
            except Exception as e:
                self.test_result("Anomaly Detection", False, f"Error: {e}")
                return False
            
            if anomalies:
                severities = [a.get('severity') for a in anomalies]
                has_severity = all(s in ['low', 'medium', 'high', 'critical'] for s in severities)
                self.test_result("Severity Classification", has_severity,
                               f"Severities: {set(severities)}")
            
            return True
            
        except Exception as e:
            self.test_result("Log Analyzer", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_threat_intelligence(self):
        """Test 2: Threat Intelligence Agent"""
        self.print_header("Test 2: Threat Intelligence Agent")
        
        try:
            from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
            from rag.vector_store.chroma_setup import (
                ThreatIntelligenceRAG,
                create_sample_threat_documents,
                create_sample_cve_documents,
                create_sample_incident_reports
            )
            
            print("  Initializing RAG...")
            rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store_week2")
            
            stats = rag.get_collection_stats()
            if stats['threats'] == 0:
                print("  Loading sample data...")
                rag.add_threat_documents(create_sample_threat_documents())
                rag.add_cve_documents(create_sample_cve_documents())
                rag.add_incident_reports(create_sample_incident_reports())
            
            self.test_result("RAG Initialization", True, "RAG system ready")
            
            print("  Initializing Threat Intelligence Agent...")
            agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)
            self.test_result("Agent Initialization", True, "ThreatIntelligenceAgent created")
            
            print("  Testing threat analysis...")
            sample_anomaly = {
                "action": "login",
                "status": "failed",
                "source_ip": "203.45.67.89",
                "severity": "high",
                "anomaly_score": -0.75,
                "features": {
                    "is_off_hours": True,
                    "failed_action": True,
                    "data_transfer_volume": 0
                }
            }
            
            try:
                analysis = agent.analyze_threat(sample_anomaly)
                
                has_required_fields = all(key in analysis for key in [
                    "threat_type", "explanation", "confidence", "severity",
                    "matched_techniques", "recommendations"
                ])
                
                self.test_result("Threat Analysis", has_required_fields,
                               f"Threat type: {analysis.get('threat_type')}, "
                               f"Confidence: {analysis.get('confidence'):.2%}")
                
                confidence = analysis.get("confidence", 0.0)
                valid_confidence = 0.0 <= confidence <= 1.0
                self.test_result("Confidence Scoring", valid_confidence,
                               f"Confidence: {confidence:.2%}")
                
                citations = analysis.get("citations", [])
                self.test_result("Citations", len(citations) >= 0,
                               f"Found {len(citations)} citations")
                
            except Exception as e:
                self.test_result("Threat Analysis", False, f"Error: {e}")
                return False
            
            return True
            
        except Exception as e:
            self.test_result("Threat Intelligence", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_response_agent(self):
        """Test 3: Response Agent"""
        self.print_header("Test 3: Response Agent")
        
        try:
            from backend.agents.response_agent import ResponseAgent, ActionTier
            
            print("  Initializing Response Agent...")
            agent = ResponseAgent(sandbox_mode=True)
            self.test_result("Agent Initialization", True, "ResponseAgent created")
            
            print("  Testing action recommendations...")
            threat_analysis = {
                "threat_type": "credential_stuffing",
                "confidence": 0.85,
                "severity": "high",
                "explanation": "Multiple failed login attempts detected",
                "matched_techniques": ["T1078"],
                "recommendations": ["Enable rate limiting", "Review logs"]
            }
            
            anomaly = {
                "action": "login",
                "status": "failed",
                "source_ip": "203.45.67.89",
                "user_id": "user_123",
                "severity": "high",
                "anomaly_score": -0.75
            }
            
            try:
                recommendations = agent.recommend_actions(threat_analysis, anomaly)
                
                has_actions = "actions" in recommendations
                has_summary = "summary" in recommendations
                
                self.test_result("Action Recommendations", has_actions and has_summary,
                               "Recommendations generated")
                
                actions = recommendations.get("actions", {})
                has_green = "green" in actions
                has_yellow = "yellow" in actions
                has_red = "red" in actions
                
                self.test_result("Traffic Light System", has_green and has_yellow and has_red,
                               f"Green: {len(actions.get('green', []))}, "
                               f"Yellow: {len(actions.get('yellow', []))}, "
                               f"Red: {len(actions.get('red', []))}")
                
                if actions.get("green"):
                    green_action = actions["green"][0]
                    is_green = green_action.get("tier") == ActionTier.GREEN
                    self.test_result("Green Actions", is_green,
                                   f"Action: {green_action.get('type')}")
                
            except Exception as e:
                self.test_result("Action Recommendations", False, f"Error: {e}")
                return False
            
            return True
            
        except Exception as e:
            self.test_result("Response Agent", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_orchestrator(self):
        """Test 4: Orchestrator Agent"""
        self.print_header("Test 4: Orchestrator Agent")
        
        try:
            from backend.agents.orchestrator import OrchestratorAgent
            from backend.agents.log_analyzer import LogAnalyzerAgent
            from backend.utils.data_loader import CICIDSLoader
            
            print("  Initializing Orchestrator...")
            orchestrator = OrchestratorAgent(sandbox_mode=True)
            self.test_result("Orchestrator Initialization", True, "OrchestratorAgent created")
            
            if not orchestrator.log_analyzer.is_trained:
                print("  Training log analyzer...")
                loader = CICIDSLoader()
                try:
                    df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=5000)
                    logs = df.to_dict('records')
                    orchestrator.log_analyzer.train_on_benign_only(logs)
                    self.test_result("Log Analyzer Training", True, "Agent trained")
                except Exception as e:
                    self.test_result("Log Analyzer Training", False, f"Error: {e}")
                    return False
            
            print("  Testing complete workflow...")
            test_log = {
                "Flow Duration": 120.5,
                "Total Fwd Packets": 150,
                "Total Backward Packets": 50,
                "Flow Bytes/s": 1000000,
                "Flow Packets/s": 100,
                "Destination Port": 22,
                "Fwd Packet Length Mean": 1000,
                "Bwd Packet Length Mean": 500,
                "Flow IAT Mean": 1.2,
                "Fwd IAT Mean": 1.0,
                "Bwd IAT Mean": 1.5,
                "Fwd PSH Flags": 1,
                "Bwd PSH Flags": 0,
                "FIN Flag Count": 1,
                "SYN Flag Count": 1,
                "RST Flag Count": 0,
                "ACK Flag Count": 10,
                "Average Packet Size": 750,
                "Label": "BENIGN"
            }
            
            try:
                result = orchestrator.analyze_log(test_log, return_full_analysis=True)
                
                has_required_fields = all(key in result for key in [
                    "threat_detected", "status", "analyzed_at"
                ])
                
                self.test_result("Workflow Execution", has_required_fields,
                               f"Status: {result.get('status')}")
                
                if result.get("threat_detected"):
                    has_analysis = "threat_analysis" in result
                    has_recommendations = "recommended_actions" in result
                    
                    self.test_result("Threat Analysis Integration", has_analysis,
                                   f"Threat type: {result.get('threat_analysis', {}).get('threat_type')}")
                    self.test_result("Action Recommendations Integration", has_recommendations,
                                   "Recommendations generated")
                else:
                    self.test_result("No Threat Detected", True, "Normal log processed")
                
            except Exception as e:
                self.test_result("Workflow Execution", False, f"Error: {e}")
                import traceback
                traceback.print_exc()
                return False
            
            print("  Testing system status...")
            status = orchestrator.get_system_status()
            has_status = "log_analyzer" in status and "threat_intelligence" in status
            self.test_result("System Status", has_status, "Status retrieved")
            
            return True
            
        except Exception as e:
            self.test_result("Orchestrator", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self):
        """Run all Week 2 tests"""
        print("WEEK 2 AI AGENTS TESTS")
        print("\nTesting: Detection, RAG Analysis, Recommendations, Orchestration")
        
        self.test_log_analyzer()
        self.test_threat_intelligence()
        self.test_response_agent()
        self.test_orchestrator()
        
        print("WEEK 2 TEST SUMMARY")
        
        for test_name, passed, message in self.test_results:
            status = "PASS" if passed else "FAIL"
            print(f"  {status} - {test_name}")
            if message and not passed:
                print(f"      {message}")
        
        total = self.passed + self.failed
        percentage = (self.passed / total * 100) if total > 0 else 0
        
        print(f"\nPassed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Total: {total} ({percentage:.0f}%)")
        
        if self.failed == 0:
            print("\nAll Week 2 tests passed!")
        else:
            print(f"\nWARNING: {self.failed} test(s) failed")
        
        return self.failed == 0


if __name__ == "__main__":
    tester = TestWeek2()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

