"""
tests/test_pipeline.py
End-to-end integration tests for Week 1
"""
import pytest
import json
import time
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestLogPreprocessing:
    """Test log preprocessing pipeline"""
    
    def test_pii_anonymization(self):
        """Test that PII is properly anonymized"""
        from backend.utils.preprocessor import LogPreprocessor
        
        preprocessor = LogPreprocessor()
        raw_log = {
            'timestamp': '2024-01-15 14:30:45',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'user_id': 'john.doe',
            'action': 'LOGIN',
            'object': '/admin',
            'result': 'SUCCESS',
            'protocol': 'HTTPS',
            'port': 443,
            'bytes_sent': 2048,
            'bytes_received': 4096,
            'duration': 45.5,
            'metadata': {'email': 'test@company.com'}
        }
        
        processed = preprocessor.process_log(raw_log)
        
        # Verify anonymization
        assert processed['source_ip'] != '192.168.1.100'
        assert processed['user_id'] != 'john.doe'
        assert processed['user_id'].startswith('USER_')
        assert '[REDACTED_EMAIL]' in processed['metadata']['email']
        print(" PII anonymization working")
    
    def test_format_normalization(self):
        """Test log format normalization"""
        from backend.utils.preprocessor import LogPreprocessor
        
        preprocessor = LogPreprocessor()
        raw_log = {
            'timestamp': '2024-01-15 14:30:45',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'username': 'jane.smith',
            'event': 'LOGIN',
            'object': '/admin',
            'result': 'SUCCESS',
            'protocol': 'https',
            'port': '443',
            'bytes_sent': '2048',
            'bytes_received': '4096',
            'duration': '45.5'
        }
        
        normalized = preprocessor.normalize_format(raw_log)
        
        assert normalized['user_id'] == 'jane.smith'
        assert normalized['action'] == 'login'
        assert normalized['protocol'] == 'HTTPS'
        assert isinstance(normalized['port'], int)
        assert normalized['bytes_sent'] == 2048
        print("Format normalization working")
    
    def test_feature_extraction(self):
        """Test ML feature extraction"""
        from backend.utils.preprocessor import LogPreprocessor
        
        preprocessor = LogPreprocessor()
        raw_log = {
            'timestamp': '2024-01-15 02:15:45',  # Off-hours
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'user_id': 'user1',
            'action': 'FAILED_LOGIN',
            'object': '/admin',
            'result': 'FAILED',
            'protocol': 'HTTPS',
            'port': 443,
            'bytes_sent': 100,
            'bytes_received': 200,
            'duration': 350  # Long duration
        }
        
        processed = preprocessor.process_log(raw_log)
        features = processed['features']
        
        assert features['is_off_hours'] == True
        assert features['failed_action'] == True
        assert features['long_duration'] == True
        assert features['is_https'] == True
        print("Feature extraction working")


class TestRAGSystem:
    """Test RAG vector store"""
    
    def test_vector_store_initialization(self):
        """Test ChromaDB initialization"""
        from rag.vector_store.chroma_setup import ThreatIntelligenceRAG
        
        rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store")
        stats = rag.get_collection_stats()
        
        assert 'threats' in stats
        assert 'cves' in stats
        assert 'incidents' in stats
        print(" Vector store initialization working")
    
    def test_threat_document_indexing(self):
        """Test indexing threat documents"""
        from rag.vector_store.chroma_setup import (
            ThreatIntelligenceRAG, 
            create_sample_threat_documents
        )
        
        rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store")
        docs = create_sample_threat_documents()
        rag.add_threat_documents(docs)
        
        stats = rag.get_collection_stats()
        assert stats['threats'] >= len(docs)
        print(" Threat document indexing working")
    
    def test_threat_retrieval(self):
        """Test threat search and retrieval"""
        from rag.vector_store.chroma_setup import (
            ThreatIntelligenceRAG,
            create_sample_threat_documents
        )
        
        rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store")
        docs = create_sample_threat_documents()
        rag.add_threat_documents(docs)
        
        results = rag.search_threats("unauthorized access patterns")
        
        assert len(results) > 0
        assert 'document' in results[0]
        assert 'metadata' in results[0]
        print(" Threat retrieval working")


class TestDatabase:
    """Test database operations"""
    
    def test_database_initialization(self):
        """Test database schema creation"""
        from backend.utils.database import SecurityLogDatabase
        
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        stats = db.get_statistics()
        
        assert 'total_logs' in stats
        assert 'total_alerts' in stats
        print(" Database initialization working")
    
    def test_log_insertion(self):
        """Test log insertion into database"""
        from backend.utils.database import SecurityLogDatabase
        from backend.utils.preprocessor import LogPreprocessor, create_sample_logs
        
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        preprocessor = LogPreprocessor()
        
        sample = create_sample_logs()[0]
        processed = preprocessor.process_log(sample)
        log_id = db.insert_log(processed)
        
        assert isinstance(log_id, int)
        assert log_id > 0
        print(" Log insertion working")
    
    def test_alert_generation(self):
        """Test alert insertion"""
        from backend.utils.database import SecurityLogDatabase
        from backend.utils.preprocessor import LogPreprocessor, create_sample_logs
        
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        preprocessor = LogPreprocessor()
        
        sample = create_sample_logs()[0]
        processed = preprocessor.process_log(sample)
        log_id = db.insert_log(processed)
        
        alert_id = db.insert_alert(
            log_id, 'TEST_ALERT', 'HIGH',
            'Test alert', 'Test threat match'
        )
        
        assert isinstance(alert_id, int)
        assert alert_id > 0
        print(" Alert generation working")


class TestStreamProcessor:
    """Test streaming pipeline"""
    
    def test_stream_processor_startup(self):
        """Test stream processor initialization"""
        from backend.utils.database import SecurityLogDatabase, StreamProcessor
        from backend.utils.preprocessor import LogPreprocessor
        
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        preprocessor = LogPreprocessor()
        stream = StreamProcessor(db, preprocessor)
        
        stream.start()
        time.sleep(0.5)
        
        assert stream.running == True
        stats = stream.get_stats()
        assert 'queue_size' in stats
        
        stream.stop()
        print(" Stream processor startup working")
    
    def test_end_to_end_pipeline(self):
        """Test complete data pipeline"""
        from backend.utils.database import SecurityLogDatabase, StreamProcessor
        from backend.utils.preprocessor import LogPreprocessor, create_sample_logs
        
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        preprocessor = LogPreprocessor()
        stream = StreamProcessor(db, preprocessor)
        
        stream.start()
        
        # Submit logs
        logs = create_sample_logs()
        for log in logs:
            stream.submit_log(log)
        
        time.sleep(2)  # Wait for processing
        
        # Verify processing
        stats = stream.get_stats()
        assert stats['processed'] >= len(logs)
        
        db_stats = db.get_statistics()
        assert db_stats['total_logs'] > 0
        
        stream.stop()
        print(" End-to-end pipeline working")


class TestIntegration:
    """Full integration tests"""
    
    def test_complete_workflow(self):
        """Test complete workflow: logs -> preprocessing -> RAG -> alerts"""
        from backend.utils.database import SecurityLogDatabase, StreamProcessor
        from backend.utils.preprocessor import LogPreprocessor, create_sample_logs
        from rag.vector_store.chroma_setup import (
            ThreatIntelligenceRAG,
            create_sample_threat_documents
        )
        
        print("\n Running complete workflow test...")
        
        # Initialize components
        db = SecurityLogDatabase(db_path="data/test_logs.db")
        preprocessor = LogPreprocessor()
        stream = StreamProcessor(db, preprocessor)
        rag = ThreatIntelligenceRAG(persist_dir="data/test_vector_store")
        
        # Load threat intelligence
        threat_docs = create_sample_threat_documents()
        rag.add_threat_documents(threat_docs)
        
        # Start streaming
        stream.start()
        
        # Ingest logs
        logs = create_sample_logs()
        for log in logs:
            stream.submit_log(log)
        
        time.sleep(2)
        
        # Verify all components
        stream_stats = stream.get_stats()
        db_stats = db.get_statistics()
        rag_stats = rag.get_collection_stats()
        
        # Assertions
        assert stream_stats['processed'] > 0, "Logs not processed"
        assert db_stats['total_logs'] > 0, "Logs not stored"
        assert rag_stats['threats'] > 0, "Threats not indexed"
        
        # Test RAG retrieval
        threat_matches = rag.search_threats("unauthorized access")
        assert len(threat_matches) > 0, "RAG retrieval failed"
        
        stream.stop()
        print("Complete workflow test passed!")
        return True


def run_all_tests():
    """Run all tests with summary"""
    print("\n" + "="*60)
    print("WEEK 1 INTEGRATION TEST SUITE")
    print("="*60 + "\n")
    
    test_classes = [
        TestLogPreprocessing,
        TestRAGSystem,
        TestDatabase,
        TestStreamProcessor,
        TestIntegration
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        print(f"\n {test_class.__name__}")
        print("-" * 40)
        
        instance = test_class()
        test_methods = [m for m in dir(instance) if m.startswith('test_')]
        
        for method_name in test_methods:
            total_tests += 1
            try:
                method = getattr(instance, method_name)
                method()
                passed_tests += 1
            except Exception as e:
                failed_tests.append(f"{test_class.__name__}.{method_name}: {str(e)}")
                print(f" {method_name} failed: {str(e)}")
    
    print("\n" + "="*60)
    print(" TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f" Failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed Tests:")
        for failure in failed_tests:
            print(f"  - {failure}")
    else:
        print("\n ALL TESTS PASSED!")
    
    return len(failed_tests) == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)