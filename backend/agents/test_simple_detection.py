"""
Test detection with manually crafted simple benign baseline
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from agents.log_analyzer import LogAnalyzerAgent

# Creating simple, consistent "benign" baseline
simple_benign_logs = []
for i in range(1000):
    log = {
        ' Label': 'BENIGN',
        'Src IP': f'192.168.1.{i % 250}',
        'Dst IP': '10.0.0.1',
        'Destination Port': 443,
        'Protocol': 'TCP',
        'Total Length of Fwd Packets': 1000 + (i % 500),  # 1KB-1.5KB
        'Total Length of Bwd Packets': 800 + (i % 300),
        'Flow Duration': 0.1 + (i % 50) / 1000,  # 0.1-0.15 sec
        'Flow Start': '2025-01-15 10:00:00'
    }
    simple_benign_logs.append(log)

# Train on simple baseline
agent = LogAnalyzerAgent(contamination=0.05)
print("Training on simple benign baseline...")
stats = agent.train(simple_benign_logs)
print(f"Stats: {stats}")

# Test with extreme anomaly
extreme_log = {
    ' Label': 'ATTACK',
    'Src IP': '1.1.1.1',
    'Dst IP': '10.0.0.1',
    'Destination Port': 9999,
    'Protocol': 'TCP',
    'Total Length of Fwd Packets': 95000000,  
    'Total Length of Bwd Packets': 100,
    'Flow Duration': 0.001,
    'Flow Start': '2025-01-15 03:00:00'
}

anomalies, results = agent.detect_anomalies([extreme_log])

print(f"\n Detection Results:")
print(f"   Threat detected: {len(anomalies) > 0}")
if anomalies:
    print(f"   Severity: {anomalies[0]['severity']}")
    print(f"   Score: {anomalies[0]['anomaly_score']:.4f}")
else:
    print("    No threat detected (this is the problem!)")