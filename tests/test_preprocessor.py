import pandas as pd
from backend.utils.preprocessor import LogPreprocessor

preprocessor = LogPreprocessor()

cicids_files = [
    "data/raw/cicids/Friday-WorkingHours-Afternoon-DDos-pcap_ISCX.csv",
    "data/raw/cicids/Friday-WorkingHours-Afternoon-PortScan-pcap_ISCX.csv",
    "data/raw/cicids/Friday-WorkingHours-Morning-pcap_ISCX.csv",
    "data/raw/cicids/Monday-WorkingHours-pcap_ISCX.csv",
    "data/raw/cicids/Thursday-WorkingHours-Afternoon-Infilteration-pcap_ISCX.csv",
    "data/raw/cicids/Thursday-WorkingHours-Morning-WebAttacks-pcap_ISCX.csv",
    "data/raw/cicids/Tuesday-WorkingHours-pcap_ISCX.csv",
    "data/raw/cicids/Wednesday-workingHours-pcap_ISCX.csv"
]


all_logs = []
for file in cicids_files:
    df = pd.read_csv(file)
    all_logs.extend(df.to_dict(orient='records'))

# Process logs
processed_logs = preprocessor.process_batch(all_logs)

for i, log in enumerate(processed_logs[:5], 1):
    print(f"--- Log {i} ---")
    print(f"User ID (hashed): {log.get('user_id')}")
    print(f"Source IP (hashed): {log.get('source_ip')}")
    print(f"Destination IP (hashed): {log.get('destination_ip')}")
    print(f"Action: {log.get('action')} | Status: {log.get('status')}")
    print(f"Features: {log.get('features')}")
    print(f"Processed At: {log.get('processed_at')}")
    print()
