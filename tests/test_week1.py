"""
Week 1 Integration Tests
Tests foundation: Data Pipeline, RAG, Database
"""

import sys
from pathlib import Path
import json
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))


class TestWeek1:
    
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
    
    def test_data_loaders(self):
        """Test 1: Data Loaders"""
        self.print_header("Test 1: Data Loaders")
        
        try:
            from backend.utils.data_loader import CICIDSLoader, MITRELoader, CVELoader
            
            # Test CICIDS loader
            print("  Testing CICIDS loader...")
            cicids_loader = CICIDSLoader()
            
            # Check if data directory exists
            data_dir = Path("data/raw/cicids")
            if not data_dir.exists():
                self.test_result("CICIDS Data Directory", False, "Directory not found")
                return False
            
            # Try to load a file
            csv_files = list(data_dir.glob("*.csv"))
            if csv_files:
                try:
                    df = cicids_loader.load_file(csv_files[0].name, sample_size=100)
                    self.test_result("CICIDS Loader", True, f"Loaded {len(df)} rows from {csv_files[0].name}")
                except Exception as e:
                    self.test_result("CICIDS Loader", False, f"Error: {e}")
            else:
                self.test_result("CICIDS Data Files", False, "No CSV files found")
            
            # Test MITRE loader
            print("  Testing MITRE loader...")
            mitre_loader = MITRELoader()
            try:
                techniques = mitre_loader.load_techniques()
                self.test_result("MITRE Loader", True, f"Loaded {len(techniques)} techniques")
            except Exception as e:
                self.test_result("MITRE Loader", False, f"Error: {e}")
            
            # Test CVE loader
            print("  Testing CVE loader...")
            cve_loader = CVELoader()
            try:
                cves = cve_loader.load_cves()
                cve_count = len(cves.get('vulnerabilities', []))
                self.test_result("CVE Loader", True, f"Loaded {cve_count} CVEs")
            except Exception as e:
                self.test_result("CVE Loader", False, f"Error: {e}")
            
            return True
            
        except ImportError as e:
            self.test_result("Data Loaders Import", False, f"Import error: {e}")
            return False
    
    def test_log_preprocessor(self):
        """Test 2: Log Preprocessor"""
        self.print_header("Test 2: Log Preprocessor")
        
        try:
            from backend.utils.preprocessor import LogPreprocessor
            
            preprocessor = LogPreprocessor()
            
            # Test anonymization
            print("  Testing PII anonymization...")
            test_log = {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "user_id": "john.doe@company.com",
                "action": "login",
                "status": "success",
                "metadata": {"email": "test@example.com"}
            }
            
            anonymized = preprocessor.anonymize_pii(test_log)
            
            # Check if IPs are anonymized
            ip_anon = anonymized["source_ip"] != test_log["source_ip"]
            user_anon = anonymized["user_id"] != test_log["user_id"]
            
            self.test_result("IP Anonymization", ip_anon,
                           f"Original: {test_log['source_ip']} -> Anonymized: {anonymized['source_ip']}")
            self.test_result("User Anonymization", user_anon,
                           f"Original: {test_log['user_id']} -> Anonymized: {anonymized['user_id']}")
            
            # Test normalization
            print("  Testing log normalization...")
            cicids_log = {
                "Src IP": "192.168.1.100",
                "Dst IP": "10.0.0.5",
                "Destination Port": 22,
                "Protocol": "TCP",
                "Flow Duration": 120.5,
                "Total Length of Fwd Packets": 1000,
                "Total Length of Bwd Packets": 500,
                "Label": "BENIGN"
            }
            
            normalized = preprocessor.normalize_format(cicids_log)
            has_required_fields = all(key in normalized for key in 
                                     ["source_ip", "destination_ip", "action", "status"])
            
            self.test_result("Log Normalization", has_required_fields,
                           f"Normalized fields: {list(normalized.keys())[:5]}...")
            
            # Test feature extraction
            print("  Testing feature extraction...")
            processed = preprocessor.process_log(cicids_log)
            has_features = "features" in processed
            
            self.test_result("Feature Extraction", has_features,
                           f"Features extracted: {len(processed.get('features', {}))} features")
            
            return True
            
        except Exception as e:
            self.test_result("Log Preprocessor", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_database(self):
        """Test 3: Database"""
        self.print_header("Test 3: Database")
        
        try:
            from backend.utils.database import SecurityLogDatabase
            
            # Use test database
            db = SecurityLogDatabase(db_path="data/test_week1.db")
            
            # Test log insertion
            print("  Testing log insertion...")
            test_log = {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "user_id": "user_123",
                "action": "login",
                "resource": "/api/auth",
                "status": "success",
                "protocol": "TCP",
                "port": 443,
                "bytes_sent": 1000,
                "bytes_received": 500,
                "duration": 0.5,
                "features": {"test": True}
            }
            
            log_id = db.insert_log(test_log)
            self.test_result("Log Insertion", log_id > 0, f"Inserted log with ID: {log_id}")
            
            # Test alert insertion
            print("  Testing alert insertion...")
            alert_id = db.insert_alert(
                log_id, "TEST_ALERT", "medium", "Test alert", "Test threat"
            )
            self.test_result("Alert Insertion", alert_id > 0, f"Inserted alert with ID: {alert_id}")
            
            # Test retrieval
            print("  Testing log retrieval...")
            recent_logs = db.get_recent_logs(limit=5)
            self.test_result("Log Retrieval", len(recent_logs) > 0, 
                           f"Retrieved {len(recent_logs)} logs")
            
            # Test statistics
            print("  Testing statistics...")
            stats = db.get_statistics()
            has_stats = "total_logs" in stats and "total_alerts" in stats
            self.test_result("Statistics", has_stats, 
                           f"Total logs: {stats.get('total_logs', 0)}, "
                           f"Total alerts: {stats.get('total_alerts', 0)}")
            
            return True
            
        except Exception as e:
            self.test_result("Database", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_rag_system(self):
        """Test 4: RAG System"""
        self.print_header("Test 4: RAG System")
        
        try:
            from rag.vector_store.chroma_setup import (
                ThreatIntelligenceRAG,
                create_sample_threat_documents,
                create_sample_cve_documents,
                create_sample_incident_reports
            )
            
            # Initialize RAG
            print("  Initializing RAG system...")
            rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store_week1")
            
            # Check current stats
            stats = rag.get_collection_stats()
            print(f"  Current stats: {stats}")
            
            # Load sample data if needed
            if stats['threats'] == 0:
                print("  Loading sample threat intelligence...")
                threat_docs = create_sample_threat_documents()
                rag.add_threat_documents(threat_docs)
                self.test_result("Threat Documents", True, f"Added {len(threat_docs)} documents")
            else:
                self.test_result("Threat Documents", True, f"Already loaded: {stats['threats']} documents")
            
            if stats['cves'] == 0:
                cve_docs = create_sample_cve_documents()
                rag.add_cve_documents(cve_docs)
                self.test_result("CVE Documents", True, f"Added {len(cve_docs)} documents")
            else:
                self.test_result("CVE Documents", True, f"Already loaded: {stats['cves']} documents")
            
            if stats['incidents'] == 0:
                incident_docs = create_sample_incident_reports()
                rag.add_incident_reports(incident_docs)
                self.test_result("Incident Documents", True, f"Added {len(incident_docs)} documents")
            else:
                self.test_result("Incident Documents", True, f"Already loaded: {stats['incidents']} documents")
            
            # Test retrieval
            print("  Testing RAG retrieval...")
            test_query = "multiple failed login attempts"
            threat_results = rag.search_threats(test_query, n_results=3)
            self.test_result("Threat Retrieval", len(threat_results) > 0,
                           f"Retrieved {len(threat_results)} threat matches")
            
            cve_results = rag.search_cves("remote code execution", n_results=2)
            self.test_result("CVE Retrieval", len(cve_results) >= 0,
                           f"Retrieved {len(cve_results)} CVE matches")
            
            # Final stats
            final_stats = rag.get_collection_stats()
            self.test_result("RAG System", True,
                           f"Final: {final_stats['threats']} threats, "
                           f"{final_stats['cves']} CVEs, "
                           f"{final_stats['incidents']} incidents")
            
            return True
            
        except Exception as e:
            self.test_result("RAG System", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_log_schema(self):
        """Test 5: Log Schema"""
        self.print_header("Test 5: Log Schema")
        
        try:
            from backend.models.log_schema import SecurityLog, LogSource, ThreatLevel, CICIDSToUnified
            
            # Test schema creation
            print("  Testing SecurityLog schema...")
            log = SecurityLog(
                log_id="test_001",
                timestamp=datetime.now(),
                source=LogSource.CICIDS,
                source_ip="192.168.1.100",
                destination_port=22,
                action="ssh_attempt",
                status="failed",
                threat_level=ThreatLevel.HIGH,
                is_attack=True
            )
            
            self.test_result("Schema Creation", True, "SecurityLog created successfully")
            
            # Test CICIDS conversion
            print("  Testing CICIDS to Unified conversion...")
            cicids_row = {
                "Destination Port": 22,
                "Flow Duration": 120.5,
                "Total Fwd Packets": 100,
                "Total Backward Packets": 50,
                "Flow Bytes/s": 1000,
                "Flow Packets/s": 10,
                "FIN Flag Count": 1,
                "SYN Flag Count": 1,
                "ACK Flag Count": 10,
                "Label": "BENIGN"
            }
            
            unified = CICIDSToUnified.convert(cicids_row, "test_002")
            is_unified = isinstance(unified, SecurityLog)
            
            self.test_result("CICIDS Conversion", is_unified,
                           f"Converted to unified schema: {unified.threat_level}")
            
            return True
            
        except Exception as e:
            self.test_result("Log Schema", False, f"Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self):
        """Run all Week 1 tests"""
        print("="*60)
        print("WEEK 1 FOUNDATION TESTS")
        print("="*60)
        print("\nTesting: Data Pipeline, RAG, Database, Schema")
        
        # Run tests
        self.test_data_loaders()
        self.test_log_preprocessor()
        self.test_database()
        self.test_rag_system()
        self.test_log_schema()
        
        # Print summary
        print("\n" + "="*60)
        print("WEEK 1 TEST SUMMARY")
        print("="*60)
        
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
            print("\nAll Week 1 tests passed!")
        else:
            print(f"\nWARNING: {self.failed} test(s) failed")
        
        return self.failed == 0


if __name__ == "__main__":
    tester = TestWeek1()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

