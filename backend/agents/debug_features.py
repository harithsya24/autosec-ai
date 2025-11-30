"""
Debug feature extraction to see what the model actually sees
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from agents.log_analyzer import LogAnalyzerAgent
from utils.preprocessor import LogPreprocessor

# Extreme anomaly log
extreme_log = {
    ' Label': 'ATTACK',
    'Src IP': '1.1.1.1',
    'Dst IP': '10.0.0.1',
    'Destination Port': 9999,
    'Protocol': 'TCP',
    'Total Length of Fwd Packets': 999999999,  # 999 MB!
    'Total Length of Bwd Packets': 1,
    'Flow Duration': 0.001,
    'Flow Start': '2025-01-15 03:00:00'
}

# Normal log
normal_log = {
    ' Label': 'BENIGN',
    'Src IP': '192.168.1.100',
    'Dst IP': '10.0.0.1',
    'Destination Port': 443,
    'Protocol': 'TCP',
    'Total Length of Fwd Packets': 1500,
    'Total Length of Bwd Packets': 800,
    'Flow Duration': 0.2,
    'Flow Start': '2025-01-15 10:00:00'
}

agent = LogAnalyzerAgent()
preprocessor = LogPreprocessor()

print(" Feature Extraction Debug\n")
print("="*60)

for label, raw_log in [("NORMAL", normal_log), ("EXTREME ANOMALY", extreme_log)]:
    print(f"\n{label}:")
    print(f"  Raw bytes_sent: {raw_log['Total Length of Fwd Packets']:,}")
    print(f"  Raw bytes_received: {raw_log['Total Length of Bwd Packets']:,}")
    print(f"  Raw duration: {raw_log['Flow Duration']}")
    
    # Process through preprocessor
    processed = preprocessor.process_log(raw_log)
    print(f"\n  Processed bytes_sent: {processed['bytes_sent']:,}")
    print(f"  Processed bytes_received: {processed['bytes_received']:,}")
    print(f"  Processed duration: {processed['duration']}")
    
    # Extract ML features
    features_df = agent.extract_ml_features([processed])
    print(f"\n  ML Features:")
    for col in features_df.columns:
        print(f"    {col}: {features_df[col].values[0]}")