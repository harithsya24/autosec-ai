from backend.utils.preprocessor import LogPreprocessor, create_sample_logs

preprocessor = LogPreprocessor()
sample_logs = create_sample_logs()

processed_logs = preprocessor.process_batch(sample_logs)

for i, log in enumerate(processed_logs, 1):
    print(f"--- Log {i} ---")
    print(f"User ID (hashed): {log['user_id']}")
    print(f"Source IP (hashed): {log['source_ip']}")
    print(f"Destination IP (hashed): {log['destination_ip']}")
    print(f"Action: {log['action']} | Status: {log['status']}")
    print(f"Features: {log['features']}")
    print(f"Processed At: {log['processed_at']}")
    print()
