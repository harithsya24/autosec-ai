"""
Process Real CICIDS Attack Data
Real-world use case: Monitor network traffic and detect actual attacks
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import pandas as pd
from datetime import datetime, timedelta
from backend.utils.database import SecurityLogDatabase
from backend.agents.orchestrator import OrchestratorAgent
from backend.utils.data_loader import CICIDSLoader
from backend.models.log_schema import CICIDSToUnified
import time

def convert_cicids_to_unified(cicids_row: dict) -> dict:
    """Convert CICIDS row to unified log format"""
    label = str(cicids_row.get('Label', 'BENIGN')).strip()
    
    # Extract key fields
    source_ip = str(cicids_row.get('Source IP', '0.0.0.0'))
    dest_ip = str(cicids_row.get('Destination IP', '0.0.0.0'))
    dest_port = int(cicids_row.get('Destination Port', 0))
    flow_duration = float(cicids_row.get('Flow Duration', 0))
    
    # Determine action based on attack type
    if 'DDoS' in label or 'DoS' in label:
        action = 'network_flood'
        resource = f'/network/port_{dest_port}'
    elif 'PortScan' in label:
        action = 'port_scan'
        resource = f'/network/port_{dest_port}'
    elif 'Web' in label or 'HTTP' in label:
        action = 'web_request'
        resource = '/api/web'
    elif 'Infiltration' in label:
        action = 'data_exfiltration'
        resource = '/network/data'
    else:
        action = 'network_flow'
        resource = f'/network/port_{dest_port}'
    
    # Create unified log format
    unified_log = {
        'timestamp': datetime.now().isoformat(),  # Use current time for demo
        'source_ip': source_ip,
        'destination_ip': dest_ip,
        'user_id': f'user_{hash(source_ip) % 10000}',
        'action': action,
        'resource': resource,
        'status': 'suspicious' if label != 'BENIGN' else 'success',
        'protocol': 'TCP',
        'port': dest_port,
        'bytes_sent': int(cicids_row.get('Total Length of Fwd Packets', 0)),
        'bytes_received': int(cicids_row.get('Total Length of Bwd Packets', 0)),
        'duration': flow_duration / 1000000.0 if flow_duration > 0 else 0.0,  # Convert microseconds to seconds
        'metadata': {
            'flow_duration': flow_duration,
            'total_packets': int(cicids_row.get('Total Fwd Packets', 0) + cicids_row.get('Total Backward Packets', 0)),
            'flow_bytes_per_sec': float(cicids_row.get('Flow Bytes/s', 0)),
            'flow_packets_per_sec': float(cicids_row.get('Flow Packets/s', 0)),
            'fwd_packet_length_mean': float(cicids_row.get('Fwd Packet Length Mean', 0)),
            'bwd_packet_length_mean': float(cicids_row.get('Bwd Packet Length Mean', 0)),
            'attack_label': label
        }
    }
    
    return unified_log, label

def process_real_attacks():
    """
    Real-world use case: Process actual CICIDS attack data
    Simulates a security operations center monitoring network traffic
    """
    
    print("=" * 70)
    print("AutoSec AI - Real Threat Detection Use Case")
    print("=" * 70)
    print("\nScenario: Security Operations Center (SOC)")
    print("   Monitoring network traffic for malicious activity")
    print("   Processing real CICIDS 2017 attack dataset\n")
    
    # Initialize components
    print("Initializing system...")
    orchestrator = OrchestratorAgent(sandbox_mode=True)
    db = SecurityLogDatabase()
    loader = CICIDSLoader()
    
    # Step 1: Train on benign traffic
    print("\nStep 1: Training on benign traffic (baseline)...")
    try:
        benign_file = "Monday-WorkingHours-pcap_ISCX.csv"
        print(f"   Loading {benign_file}...")
        benign_df = loader.load_file(benign_file, sample_size=20000)
        
        # Handle different label column names
        label_col = None
        for col in ['Label', ' Label', 'label']:
            if col in benign_df.columns:
                label_col = col
                break
        
        if label_col is None:
            print("   WARNING: Could not find label column, using all data")
            label_col = 'Label'
            benign_df['Label'] = 'BENIGN'  # Assume all are benign if no label
        
        # Filter only BENIGN traffic
        benign_df = benign_df[benign_df[label_col].astype(str).str.strip() == 'BENIGN']
        print(f"   Found {len(benign_df):,} benign records")
        
        # Convert to unified format
        benign_logs = []
        for _, row in benign_df.head(15000).iterrows():
            log, _ = convert_cicids_to_unified(row.to_dict())
            benign_logs.append(log)
        
        # Train the agent
        print("   Training anomaly detection model...")
        orchestrator.log_analyzer.train_on_benign_only(benign_logs)
        print("   Model trained on benign traffic baseline")
        
    except Exception as e:
        print(f"   WARNING: Training error: {e}")
        print("   Continuing with default model...")
    
    # Step 2: Process attack files
    attack_files = [
        ("Friday-WorkingHours-Afternoon-DDos-pcap_ISCX.csv", "DDoS Attack"),
        ("Friday-WorkingHours-Afternoon-PortScan-pcap_ISCX.csv", "Port Scan Attack"),
        ("Thursday-WorkingHours-Morning-WebAttacks-pcap_ISCX.csv", "Web Attack"),
        ("Thursday-WorkingHours-Afternoon-Infilteration-pcap_ISCX.csv", "Infiltration Attack"),
    ]
    
    print("\nStep 2: Processing real attack traffic...")
    print("   Simulating real-time threat detection\n")
    
    total_threats = 0
    threats_by_type = {}
    
    for filename, attack_name in attack_files:
        print(f"   Processing: {attack_name}")
        print(f"      File: {filename}")
        
        try:
            # Load attack data
            attack_df = loader.load_file(filename, sample_size=5000)
            
            # Handle different label column names
            label_col = None
            for col in ['Label', ' Label', 'label']:
                if col in attack_df.columns:
                    label_col = col
                    break
            
            if label_col is None:
                print(f"      WARNING: Could not find label column, assuming all are attacks")
                label_col = 'Label'
                attack_df['Label'] = 'ATTACK'
            
            # Filter out BENIGN (keep only attacks)
            attack_df = attack_df[attack_df[label_col].astype(str).str.strip() != 'BENIGN']
            
            if len(attack_df) == 0:
                print(f"      WARNING: No attack records found, skipping...")
                continue
            
            print(f"      Found {len(attack_df):,} attack records")
            
            # Process attacks in batches
            batch_size = 100
            processed = 0
            
            for i in range(0, min(len(attack_df), 500), batch_size):
                batch_df = attack_df.iloc[i:i+batch_size]
                batch_threats = 0
                
                for _, row in batch_df.iterrows():
                    try:
                        # Convert to unified format
                        log, label = convert_cicids_to_unified(row.to_dict())
                        
                        # Analyze with orchestrator
                        result = orchestrator.analyze_log(log, return_full_analysis=True)
                        
                        if result.get('threat_detected'):
                            alert_id = f"threat_{datetime.now().timestamp()}_{total_threats}"
                            
                            # Extract threat information
                            threat_type = result.get('threat_analysis', {}).get('threat_type', label)
                            severity = result.get('threat_analysis', {}).get('severity', 
                                result.get('anomaly', {}).get('severity', 'medium'))
                            confidence = result.get('threat_analysis', {}).get('confidence', 0.5)
                            
                            # Store in database
                            threat_data = {
                                "alert_id": alert_id,
                                "timestamp": log.get('timestamp', datetime.now()),
                                "severity": severity,
                                "confidence": confidence,
                                "threat_type": threat_type,
                                "description": result.get('threat_analysis', {}).get('explanation', 
                                    f"{attack_name} detected in network traffic"),
                                "anomaly": result.get('anomaly', {}),
                                "status": "detected",
                                "threat_analysis": result.get('threat_analysis', {}),
                                "recommended_actions": result.get('recommended_actions', {}).get('actions', {}),
                                "executed_actions": result.get('executed_actions', []),
                                "pending_actions": result.get('pending_actions', []),
                                "matched_techniques": result.get('threat_analysis', {}).get('matched_techniques', []),
                                "affected_resources": [log.get('resource', '')]
                            }
                            
                            db.insert_threat(threat_data)
                            batch_threats += 1
                            total_threats += 1
                            
                            # Track by type
                            if threat_type not in threats_by_type:
                                threats_by_type[threat_type] = 0
                            threats_by_type[threat_type] += 1
                            
                            # Show progress
                            if batch_threats % 10 == 0:
                                print(f"         Detected {batch_threats} threats so far...")
                        
                        processed += 1
                        
                        # Small delay to simulate real-time processing
                        if processed % 50 == 0:
                            time.sleep(0.1)
                            
                    except Exception as e:
                        print(f"         WARNING: Error processing record: {e}")
                        continue
                
                print(f"      Processed {processed} records, detected {batch_threats} threats")
            
        except FileNotFoundError:
            print(f"      ERROR: File not found: {filename}")
        except Exception as e:
            print(f"      ERROR: Error processing {filename}: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 70)
    print("DETECTION SUMMARY")
    print("=" * 70)
    print(f"Total threats detected: {total_threats}")
    print(f"Threats stored in database: {total_threats}")
    print(f"\nThreats by type:")
    for threat_type, count in sorted(threats_by_type.items(), key=lambda x: x[1], reverse=True):
        print(f"   - {threat_type}: {count}")
    
    print(f"\nView threats in dashboard:")
    print(f"   http://localhost:3000")
    print(f"\nAPI endpoint:")
    print(f"   GET http://localhost:8000/api/v1/threats")
    print("\n" + "=" * 70)
    print("Real threat detection complete!")
    print("=" * 70)

if __name__ == "__main__":
    process_real_attacks()

