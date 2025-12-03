"""
Generate sample threats for testing the dashboard
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from backend.utils.database import SecurityLogDatabase
from backend.agents.orchestrator import OrchestratorAgent
from datetime import datetime, timedelta
import random

def generate_sample_threats():
    """Generate sample threats for dashboard testing"""
    
    print("Setting up orchestrator...")
    orchestrator = OrchestratorAgent(sandbox_mode=True)
    
    # Train the agent first
    print("Training agent on sample data...")
    try:
        import pandas as pd
        data_dir = Path(__file__).parent.parent / "data" / "raw" / "cicids"
        file_path = data_dir / "Friday-WorkingHours-Morning-pcap_ISCX.csv"
        
        if file_path.exists():
            df = pd.read_csv(file_path, nrows=5000)
            all_logs = df.to_dict('records')
            orchestrator.log_analyzer.train_on_benign_only(all_logs)
            print("Agent trained")
        else:
            print("WARNING: Training file not found, using default model")
    except Exception as e:
        print(f"WARNING: Training error: {e}")
    
    sample_logs = [
        {
            'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
            'source_ip': '203.45.67.89',
            'destination_ip': '192.168.1.100',
            'user_id': 'user_123',
            'action': 'login',
            'resource': '/api/auth',
            'status': 'failed',
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': 0,
            'bytes_received': 0,
            'duration': 0.5,
            'metadata': {}
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=10)).isoformat(),
            'source_ip': '198.51.100.42',
            'destination_ip': '192.168.1.50',
            'user_id': 'admin_user',
            'action': 'file_access',
            'resource': '/admin/users',
            'status': 'success',
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': 5000000,
            'bytes_received': 1000,
            'duration': 120.5,
            'metadata': {}
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
            'source_ip': '172.16.0.50',
            'destination_ip': '10.0.0.1',
            'user_id': 'service_account',
            'action': 'api_call',
            'resource': '/api/v1/users/export',
            'status': 'success',
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': 10000000,
            'bytes_received': 500,
            'duration': 45.2,
            'metadata': {}
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=20)).isoformat(),
            'source_ip': '192.168.1.200',
            'destination_ip': '192.168.1.1',
            'user_id': 'test_user',
            'action': 'login',
            'resource': '/login',
            'status': 'failed',
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': 0,
            'bytes_received': 0,
            'duration': 0.1,
            'metadata': {}
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=25)).isoformat(),
            'source_ip': '10.0.0.100',
            'destination_ip': '10.0.0.50',
            'user_id': 'user_456',
            'action': 'privilege_escalation',
            'resource': '/admin/config',
            'status': 'success',
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': 2000,
            'bytes_received': 5000,
            'duration': 2.3,
            'metadata': {}
        }
    ]
    
    print(f"\nGenerating {len(sample_logs)} sample threats...")
    
    db = SecurityLogDatabase()
    threats_created = 0
    
    for i, log in enumerate(sample_logs, 1):
        try:
            print(f"  Analyzing log {i}/{len(sample_logs)}...")
            result = orchestrator.analyze_log(log, return_full_analysis=True)
            
            if result.get('threat_detected'):
                alert_id = f"threat_{datetime.now().timestamp()}_{i}"
                
                threat_data = {
                    "alert_id": alert_id,
                    "timestamp": log.get('timestamp', datetime.now()),
                    "severity": result.get('threat_analysis', {}).get('severity', 'medium'),
                    "confidence": result.get('threat_analysis', {}).get('confidence', 0.5),
                    "threat_type": result.get('threat_analysis', {}).get('threat_type', 'Unknown'),
                    "description": result.get('threat_analysis', {}).get('explanation', 'Threat detected'),
                    "anomaly": result.get('anomaly', {}),
                    "status": "detected",
                    "threat_analysis": result.get('threat_analysis', {}),
                    "recommended_actions": result.get('recommended_actions', {}).get('actions', {}),
                    "executed_actions": result.get('executed_actions', []),
                    "pending_actions": result.get('pending_actions', []),
                    "matched_techniques": result.get('threat_analysis', {}).get('matched_techniques', []),
                    "affected_resources": [result.get('anomaly', {}).get('resource', '')] if result.get('anomaly', {}).get('resource') else []
                }
                
                db.insert_threat(threat_data)
                threats_created += 1
                print(f"    Threat created: {alert_id}")
            else:
                print(f"    WARNING: No threat detected for log {i}")
        except Exception as e:
            print(f"    ERROR: Error processing log {i}: {e}")
    
    print(f"\nGenerated {threats_created} threats in database")
    print(f"View them at: http://localhost:3000")

if __name__ == "__main__":
    generate_sample_threats()


