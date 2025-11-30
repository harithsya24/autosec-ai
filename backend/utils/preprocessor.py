"""
backend/utils/preprocessor.py
Log preprocessing, anonymization, and feature extraction
"""

import re
import hashlib
from datetime import datetime
from typing import Dict, List, Any
import pandas as pd
from pydantic import BaseModel
import os

class SecurityLog(BaseModel):
    """Unified log schema"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    user_id: str
    action: str
    resource: str
    status: str
    protocol: str
    port: int
    bytes_sent: int
    bytes_received: int
    duration: float
    metadata: Dict[str, Any]


class LogPreprocessor:
    """Handle log preprocessing, anonymization, and feature extraction"""

    def __init__(self, salt: str = "autosec_ai_salt"):
        self.salt = salt
        self.ip_mapping = {}
        self.user_mapping = {}
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def anonymize_pii(self, log: Dict[str, Any]) -> Dict[str, Any]:
        anonymized = log.copy()
        if 'source_ip' in anonymized:
            anonymized['source_ip'] = self._hash_ip(anonymized['source_ip'])
        if 'destination_ip' in anonymized:
            anonymized['destination_ip'] = self._hash_ip(anonymized['destination_ip'])
        if 'user_id' in anonymized and anonymized['user_id']:
            anonymized['user_id'] = self._hash_user(anonymized['user_id'])
        if 'metadata' in anonymized:
            anonymized['metadata'] = self._redact_emails(anonymized['metadata'])
        return anonymized

    def _hash_ip(self, ip: str) -> str:
        if ip in self.ip_mapping:
            return self.ip_mapping[ip]
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}"
                host_hash = hashlib.sha256(f"{ip}{self.salt}".encode()).hexdigest()[:8]
                hashed = f"{subnet}.X.{host_hash}"
                self.ip_mapping[ip] = hashed
                return hashed
        except:
            pass
        return "X.X.X.X"

    def _hash_user(self, user_id: str) -> str:
        if user_id in self.user_mapping:
            return self.user_mapping[user_id]
        hashed = f"USER_{hashlib.sha256(f'{user_id}{self.salt}'.encode()).hexdigest()[:8]}"
        self.user_mapping[user_id] = hashed
        return hashed

    def _redact_emails(self, metadata: Dict) -> Dict:
        redacted = {}
        for key, value in metadata.items():
            if isinstance(value, str):
                redacted[key] = self.email_pattern.sub("[REDACTED_EMAIL]", value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_emails(value)
            else:
                redacted[key] = value
        return redacted
    
    def normalize_format(self, log: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            'timestamp': self._parse_timestamp(log.get('Flow Start', datetime.now().isoformat())),  # use real column if exists
            'source_ip': log.get('Src IP', 'unknown'),
            'destination_ip': log.get('Dst IP', 'unknown'),
            'user_id': log.get('Flow ID', f"{log.get('Src IP','')}_{log.get('Dst IP','')}"),
            'action': log.get('Label', 'unknown').lower(),
            'resource': log.get('Destination Port', 0),
            'status': 'success' if log.get('Label','BENIGN') == 'BENIGN' else 'failed',
            'protocol': log.get('Protocol', 'unknown').upper(),
            'port': self._parse_int(log.get('Destination Port', 0)),
            'bytes_sent': self._parse_int(log.get('Total Length of Fwd Packets', 0)),
            'bytes_received': self._parse_int(log.get('Total Length of Bwd Packets', 0)),
            'duration': self._parse_float(log.get('Flow Duration', 0.0)),
            'metadata': {k: v for k, v in log.items() if k not in ['Flow Start','Src IP','Dst IP','Label','Protocol','Destination Port','Total Length of Fwd Packets','Total Length of Bwd Packets','Flow Duration','Flow ID']}
        }
        return normalized


    def extract_features(self, log: Dict[str, Any]) -> Dict[str, Any]:
        features = {
            'hour_of_day': log['timestamp'].hour,
            'day_of_week': log['timestamp'].weekday(),
            'is_off_hours': log['timestamp'].hour not in range(8, 18),
            'is_weekend': log['timestamp'].weekday() >= 5,
            'bytes_ratio': self._safe_divide(log['bytes_sent'], log['bytes_received'] + 1),
            'high_port': log['port'] > 1024,
            'failed_action': log['status'] in ['failed', 'error', 'denied'],
            'is_https': log['protocol'] == 'HTTPS',
            'data_transfer_volume': log['bytes_sent'] + log['bytes_received'],
            'long_duration': log['duration'] > 300,
        }
        return features

    def _parse_timestamp(self, ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%b/%Y:%H:%M:%S']:
                try:
                    return datetime.strptime(ts, fmt)
                except:
                    continue
        return datetime.now()

    def _parse_int(self, val: Any) -> int:
        try:
            return int(val)
        except:
            return 0

    def _parse_float(self, val: Any) -> float:
        try:
            return float(val)
        except:
            return 0.0

    def _safe_divide(self, a: float, b: float) -> float:
        try:
            return a / b if b != 0 else 0.0
        except:
            return 0.0

    def process_log(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self.normalize_format(raw_log)
        anonymized = self.anonymize_pii(normalized)
        features = self.extract_features(normalized)
        return {
            **anonymized,
            'features': features,
            'processed_at': datetime.now().isoformat()
        }

    def process_batch(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.process_log(log) for log in logs]

    def load_cicids_csv(self, data_dir: str = "data/raw/cicids/") -> List[Dict[str, Any]]:
        """Load all CICIDS CSV files into a list of log dicts"""
        all_logs = []
        for file_name in os.listdir(data_dir):
            if file_name.endswith(".csv"):
                df = pd.read_csv(os.path.join(data_dir, file_name))
                for _, row in df.iterrows():
                    log = row.to_dict()
                    # Flatten metadata if needed
                    log['metadata'] = {k: v for k, v in log.items() if k not in ['timestamp', 'source_ip', 'dest_ip', 'user_id', 'username', 'action', 'event', 'resource', 'object', 'status', 'result', 'protocol', 'port', 'bytes_sent', 'bytes_received', 'duration']}
                    all_logs.append(log)
        return all_logs


if __name__ == "__main__":
    preprocessor = LogPreprocessor()
    
    # Load real CICIDS logs
    raw_logs = preprocessor.load_cicids_csv()
    processed_logs = preprocessor.process_batch(raw_logs)
    
    print(f"Processed {len(processed_logs)} logs from CICIDS dataset.\n")
    for i, log in enumerate(processed_logs[:5], 1):  # Print first 5 logs
        print(f"Log {i}: User={log['user_id']}, Source IP={log['source_ip']}, Action={log['action']}")
