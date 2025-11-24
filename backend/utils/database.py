"""
backend/utils/database.py
Database setup and real-time streaming pipeline
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any
import threading
from queue import Queue
import time

# Fix Python 3.12 datetime deprecation
sqlite3.register_adapter(datetime, lambda val: val.isoformat())
sqlite3.register_converter("DATETIME", lambda val: datetime.fromisoformat(val.decode()))


class SecurityLogDatabase:
    """SQLite database for processed security logs"""

    def __init__(self, db_path: str = "data/security_logs.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()

        # Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                status TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                duration REAL DEFAULT 0,
                features JSON,
                processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                threat_match TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES logs(id)
            )
        ''')

        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                user_id TEXT,
                count INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                context JSON
            )
        ''')

        # Create indexes separately
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status)')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id)')

        conn.commit()
        conn.close()

    def insert_log(self, log: Dict[str, Any]) -> int:
        """Insert processed log into database"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO logs 
            (timestamp, source_ip, destination_ip, user_id, action, resource, 
             status, protocol, port, bytes_sent, bytes_received, duration, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log.get('timestamp', datetime.now()),
            log.get('source_ip'),
            log.get('destination_ip'),
            log.get('user_id'),
            log.get('action'),
            log.get('resource'),
            log.get('status'),
            log.get('protocol'),
            log.get('port'),
            log.get('bytes_sent', 0),
            log.get('bytes_received', 0),
            log.get('duration', 0),
            json.dumps(log.get('features', {}))
        ))

        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id

    def insert_alert(self, log_id: int, alert_type: str, severity: str,
                     description: str, threat_match: str) -> int:
        """Insert alert into database"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO alerts 
            (log_id, alert_type, severity, description, threat_match)
            VALUES (?, ?, ?, ?, ?)
        ''', (log_id, alert_type, severity, description, threat_match))

        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        return alert_id

    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM logs
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))

        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs

    def get_alerts(self, severity: str = None, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if severity:
            cursor.execute('''
                SELECT a.*, l.source_ip, l.user_id, l.action
                FROM alerts a
                JOIN logs l ON a.log_id = l.id
                WHERE a.severity = ?
                ORDER BY a.created_at DESC
                LIMIT ?
            ''', (severity, limit))
        else:
            cursor.execute('''
                SELECT a.*, l.source_ip, l.user_id, l.action
                FROM alerts a
                JOIN logs l ON a.log_id = l.id
                ORDER BY a.created_at DESC
                LIMIT ?
            ''', (limit,))

        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts

    def get_statistics(self) -> Dict:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM logs')
        log_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM alerts')
        alert_count = cursor.fetchone()[0]

        cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
        severity_breakdown = dict(cursor.fetchall())

        conn.close()

        return {
            'total_logs': log_count,
            'total_alerts': alert_count,
            'alerts_by_severity': severity_breakdown
        }


class StreamProcessor:
    """Real-time streaming log processor"""

    def __init__(self, db: SecurityLogDatabase, preprocessor, max_queue_size: int = 1000):
        self.db = db
        self.preprocessor = preprocessor
        self.queue = Queue(maxsize=max_queue_size)
        self.running = False
        self.stats = {
            'processed': 0,
            'failed': 0,
            'alerts_generated': 0
        }

    def start(self):
        """Start stream processor worker thread"""
        self.running = True
        worker = threading.Thread(target=self._process_stream, daemon=True)
        worker.start()
        print(" Stream processor started")

    def stop(self):
        """Stop stream processor"""
        self.running = False
        print(" Stream processor stopped")

    def submit_log(self, raw_log: Dict[str, Any]) -> bool:
        """Submit raw log to processing queue"""
        try:
            self.queue.put(raw_log, block=False)
            return True
        except:
            return False

    def _process_stream(self):
        while self.running:
            try:
                raw_log = self.queue.get(timeout=1)
                processed_log = self.preprocessor.process_log(raw_log)

                # Fill missing keys
                for key in ['timestamp', 'source_ip', 'destination_ip', 'user_id',
                            'action', 'resource', 'status', 'protocol', 'port',
                            'bytes_sent', 'bytes_received', 'duration', 'features']:
                    processed_log.setdefault(key, None)

                log_id = self.db.insert_log(processed_log)

                if self._is_suspicious(processed_log):
                    self._generate_alert(log_id, processed_log)

                self.stats['processed'] += 1

            except Exception as e:
                self.stats['failed'] += 1
                print(f" Failed to process log: {e}")

    def _is_suspicious(self, log: Dict) -> bool:
        features = log.get('features', {})
        if features.get('is_off_hours') and features.get('data_transfer_volume', 0) > 10_000_000:
            return True
        if features.get('failed_action'):
            return True
        if features.get('is_weekend') and not log['source_ip'].startswith('192.168'):
            return True
        return False

    def _generate_alert(self, log_id: int, log: Dict):
        features = log.get('features', {})

        if features.get('is_off_hours') and features.get('data_transfer_volume', 0) > 10_000_000:
            self.db.insert_alert(
                log_id, 'ANOMALY', 'HIGH',
                'Off-hours data transfer detected',
                'High volume data exfiltration pattern'
            )

        if features.get('failed_action'):
            self.db.insert_alert(
                log_id, 'FAILED_ACTION', 'MEDIUM',
                f'Failed action: {log["action"]}',
                'Potential brute force or unauthorized access'
            )

        if features.get('is_weekend') and not log['source_ip'].startswith('192.168'):
            self.db.insert_alert(
                log_id, 'WEEKEND_ACCESS', 'LOW',
                f'Weekend access detected from {log["source_ip"]}',
                'Access from external IP during weekend'
            )

        self.stats['alerts_generated'] += 1

    def get_stats(self) -> Dict:
        return {
            **self.stats,
            'queue_size': self.queue.qsize()
        }


if __name__ == "__main__":
    from backend.utils.preprocessor import LogPreprocessor, create_sample_logs

    db = SecurityLogDatabase()
    preprocessor = LogPreprocessor()
    stream = StreamProcessor(db, preprocessor)
    stream.start()

    print(" Simulating log stream...")
    sample_logs = create_sample_logs()

    for i in range(3):
        for log in sample_logs:
            stream.submit_log(log)
            time.sleep(0.1)

    time.sleep(2)

    print(f"\n Stream Stats: {stream.get_stats()}")
    print(f" Database Stats: {db.get_statistics()}")

    recent = db.get_recent_logs(3)
    print(f"\n Recent logs ({len(recent)}):")
    for log in recent:
        print(f"  - {log['timestamp']}: {log['user_id']} - {log['action']} ({log['status']})")

    alerts = db.get_alerts()
    print(f"\n Alerts ({len(alerts)}):")
    for alert in alerts:
        print(f"  - [{alert['severity']}] {alert['alert_type']}: {alert['description']}")

    stream.stop()
