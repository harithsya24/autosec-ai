"""
backend/utils/preprocessor.py
Log preprocessing, anonymization, and feature extraction
"""
import re
import hashlib
from datetime import datetime
from typing import Dict, List, Any
import json
from pydantic import BaseModel


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
        """Redact or hash personally identifiable information"""
        anonymized = log.copy()
        
        # Hash IP addresses consistently
        if 'source_ip' in anonymized:
            anonymized['source_ip'] = self._hash_ip(anonymized['source_ip'])
        if 'destination_ip' in anonymized:
            anonymized['destination_ip'] = self._hash_ip(anonymized['destination_ip'])
        
        # Hash user IDs
        if 'user_id' in anonymized and anonymized['user_id']:
            anonymized['user_id'] = self._hash_user(anonymized['user_id'])
        
        # Redact emails in metadata
        if 'metadata' in anonymized:
            anonymized['metadata'] = self._redact_emails(anonymized['metadata'])
        
        return anonymized
    
    def _hash_ip(self, ip: str) -> str:
        """Hash IP consistently while preserving subnet information"""
        if ip in self.ip_mapping:
            return self.ip_mapping[ip]
        
        # Keep first two octets for subnet analysis, hash the rest
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
        """Hash user ID consistently"""
        if user_id in self.user_mapping:
            return self.user_mapping[user_id]
        
        hashed = f"USER_{hashlib.sha256(f'{user_id}{self.salt}'.encode()).hexdigest()[:8]}"
        self.user_mapping[user_id] = hashed
        return hashed
    
    def _redact_emails(self, metadata: Dict) -> Dict:
        """Redact email addresses in metadata"""
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
        """Normalize log to unified schema"""
        normalized = {
            'timestamp': self._parse_timestamp(log.get('timestamp')),
            'source_ip': log.get('source_ip', 'unknown'),
            'destination_ip': log.get('dest_ip', log.get('destination_ip', 'unknown')),
            'user_id': log.get('user_id', log.get('username', 'unknown')),
            'action': log.get('action', log.get('event', 'unknown')).lower(),
            'resource': log.get('resource', log.get('object', 'unknown')),
            'status': log.get('status', log.get('result', 'unknown')).lower(),
            'protocol': log.get('protocol', 'unknown').upper(),
            'port': self._parse_int(log.get('port', 0)),
            'bytes_sent': self._parse_int(log.get('bytes_sent', 0)),
            'bytes_received': self._parse_int(log.get('bytes_received', 0)),
            'duration': self._parse_float(log.get('duration', 0.0)),
            'metadata': log.get('metadata', {})
        }
        return normalized
    
    def extract_features(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ML features from log"""
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
        """Parse timestamp from various formats"""
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
        """Safely parse integer"""
        try:
            return int(val)
        except:
            return 0
    
    def _parse_float(self, val: Any) -> float:
        """Safely parse float"""
        try:
            return float(val)
        except:
            return 0.0
    
    def _safe_divide(self, a: float, b: float) -> float:
        """Safely divide two numbers"""
        try:
            return a / b if b != 0 else 0.0
        except:
            return 0.0
    
    def process_log(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """Complete log processing pipeline"""
        normalized = self.normalize_format(raw_log)
        anonymized = self.anonymize_pii(normalized)
        features = self.extract_features(normalized)
        
        return {
            **anonymized,
            'features': features,
            'processed_at': datetime.now().isoformat()
        }
    
    def process_batch(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple logs"""
        return [self.process_log(log) for log in logs]


def create_sample_logs() -> List[Dict[str, Any]]:
    """Create sample raw logs for testing"""
    return [
        {
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
            'metadata': {'device': 'laptop', 'location': 'office'}
        },
        {
            'timestamp': '2024-01-15 02:15:20',
            'source_ip': '203.0.113.45',
            'dest_ip': '10.0.0.10',
            'user_id': 'admin@company.com',
            'action': 'FAILED_LOGIN',
            'object': '/dashboard',
            'result': 'FAILED',
            'protocol': 'HTTPS',
            'port': 443,
            'bytes_sent': 512,
            'bytes_received': 256,
            'duration': 2.1,
            'metadata': {'attempt': 3, 'ip_reputation': 'suspicious'}
        },
        {
            'timestamp': '2024-01-15 09:45:00',
            'source_ip': '192.168.1.101',
            'dest_ip': '10.0.0.7',
            'user_id': 'jane.smith',
            'action': 'FILE_ACCESS',
            'object': '/data/sensitive',
            'result': 'SUCCESS',
            'protocol': 'SMB',
            'port': 445,
            'bytes_sent': 1024000,
            'bytes_received': 5120000,
            'duration': 120.3,
            'metadata': {'file_size': '5MB', 'user_agent': 'SMBClient/2.1'}
        }
    ]


if __name__ == "__main__":
    preprocessor = LogPreprocessor()
    
    # Process sample logs
    sample_logs = create_sample_logs()
    processed_logs = preprocessor.process_batch(sample_logs)
    
    print(" Log preprocessing complete\n")
    for i, log in enumerate(processed_logs, 1):
        print(f"Log {i}:")
        print(f"  User: {log['user_id']}")
        print(f"  Source IP: {log['source_ip']}")
        print(f"  Action: {log['action']} - {log['status']}")
        print(f"  Features: off-hours={log['features']['is_off_hours']}, failed={log['features']['failed_action']}")
        print()