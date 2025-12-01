"""
backend/utils/database.py
Database setup and real-time streaming pipeline
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any
import threading
from queue import Queue
import time
from pathlib import Path

# Fix Python 3.12 datetime deprecation
sqlite3.register_adapter(datetime, lambda val: val.isoformat())
sqlite3.register_converter("DATETIME", lambda val: datetime.fromisoformat(val.decode()))


class SecurityLogDatabase:
    """SQLite database for processed security logs"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            # Get project root (2 levels up from backend/utils)
            project_root = Path(__file__).parent.parent.parent
            db_path = str(project_root / "data" / "security_logs.db")
        
        self.db_path = db_path
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
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

        # Threats table - stores complete threat analysis results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                alert_id TEXT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_type TEXT NOT NULL,
                description TEXT,
                anomaly_score REAL,
                source_ip TEXT,
                user_id TEXT,
                resource TEXT,
                status TEXT,
                threat_analysis JSON,
                recommended_actions JSON,
                executed_actions JSON,
                pending_actions JSON,
                matched_techniques TEXT,
                affected_resources TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_confidence ON threats(confidence)')

        conn.commit()
        conn.close()
    
    def insert_threat(self, threat_data: Dict[str, Any]) -> str:
        """Insert a complete threat analysis into the database"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        alert_id = threat_data.get('alert_id', f"threat_{datetime.now().timestamp()}")
        
        cursor.execute('''
            INSERT OR REPLACE INTO threats 
            (alert_id, timestamp, severity, confidence, threat_type, description,
             anomaly_score, source_ip, user_id, resource, status,
             threat_analysis, recommended_actions, executed_actions, pending_actions,
             matched_techniques, affected_resources)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_id,
            threat_data.get('timestamp', datetime.now()),
            threat_data.get('severity', 'medium'),
            threat_data.get('confidence', 0.5),
            threat_data.get('threat_type', 'Unknown'),
            threat_data.get('description', ''),
            threat_data.get('anomaly', {}).get('anomaly_score', 0.0),
            threat_data.get('anomaly', {}).get('source_ip', ''),
            threat_data.get('anomaly', {}).get('user_id', ''),
            threat_data.get('anomaly', {}).get('resource', ''),
            threat_data.get('status', 'detected'),
            json.dumps(threat_data.get('threat_analysis', {})),
            json.dumps(threat_data.get('recommended_actions', [])),
            json.dumps(threat_data.get('executed_actions', [])),
            json.dumps(threat_data.get('pending_actions', [])),
            ','.join(threat_data.get('matched_techniques', [])),
            ','.join(threat_data.get('affected_resources', []))
        ))
        
        conn.commit()
        conn.close()
        return alert_id
    
    def get_threats(self, limit: int = 50, severity: str = None) -> List[Dict]:
        """Get threats from database"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if severity:
            cursor.execute('''
                SELECT * FROM threats
                WHERE severity = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (severity, limit))
        else:
            cursor.execute('''
                SELECT * FROM threats
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        threats = []
        for row in cursor.fetchall():
            threat = dict(row)
            # Parse JSON fields
            if threat.get('threat_analysis'):
                threat['threat_analysis'] = json.loads(threat['threat_analysis'])
            if threat.get('recommended_actions'):
                threat['recommended_actions'] = json.loads(threat['recommended_actions'])
            if threat.get('executed_actions'):
                threat['executed_actions'] = json.loads(threat['executed_actions'])
            if threat.get('pending_actions'):
                threat['pending_actions'] = json.loads(threat['pending_actions'])
            if threat.get('matched_techniques'):
                threat['matched_techniques'] = threat['matched_techniques'].split(',') if threat['matched_techniques'] else []
            if threat.get('affected_resources'):
                threat['affected_resources'] = threat['affected_resources'].split(',') if threat['affected_resources'] else []
            threats.append(threat)
        
        conn.close()
        return threats
    
    def get_threat_by_id(self, alert_id: str) -> Dict:
        """Get a specific threat by ID"""
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threats WHERE alert_id = ?', (alert_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        threat = dict(row)
        # Parse JSON fields
        if threat.get('threat_analysis'):
            threat['threat_analysis'] = json.loads(threat['threat_analysis'])
        if threat.get('recommended_actions'):
            threat['recommended_actions'] = json.loads(threat['recommended_actions'])
        if threat.get('executed_actions'):
            threat['executed_actions'] = json.loads(threat['executed_actions'])
        if threat.get('pending_actions'):
            threat['pending_actions'] = json.loads(threat['pending_actions'])
        if threat.get('matched_techniques'):
            threat['matched_techniques'] = threat['matched_techniques'].split(',') if threat['matched_techniques'] else []
        if threat.get('affected_resources'):
            threat['affected_resources'] = threat['affected_resources'].split(',') if threat['affected_resources'] else []
        
        conn.close()
        return threat

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
                import traceback
                error_msg = str(e) if str(e) else type(e).__name__
                print(f" Failed to process log: {error_msg}")
                if os.getenv("DEBUG", "").lower() == "true":
                    traceback.print_exc()

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
    import sys
    from pathlib import Path
    # Add project root to path
    project_root = Path(__file__).parent.parent.parent
    sys.path.insert(0, str(project_root))
    
    from backend.utils.preprocessor import LogPreprocessor
    from backend.utils.data_loader import CICIDSLoader

    db = SecurityLogDatabase()
    preprocessor = LogPreprocessor()
    stream = StreamProcessor(db, preprocessor)
    stream.start()

    print(" Loading real CICIDS data...")
    # Load real CICIDS data from all available files
    # Use absolute path to ensure we find the data directory
    data_dir = project_root / "data" / "raw" / "cicids"
    loader = CICIDSLoader(data_dir=str(data_dir))
    
    # List of all CICIDS files to process
    cicids_files = [
        "Monday-WorkingHours-pcap_ISCX.csv",
        "Tuesday-WorkingHours-pcap_ISCX.csv",
        "Wednesday-workingHours-pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks-pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration-pcap_ISCX.csv",
        "Friday-WorkingHours-Morning-pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan-pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos-pcap_ISCX.csv"
    ]
    
    try:
        all_logs = []
        total_loaded = 0
        
        # Load data from all available files
        for filename in cicids_files:
            try:
                # Load each file (no sample_size limit to get all data)
                df = loader.load_file(filename, sample_size=None)
                if len(df) > 0:
                    # Convert to dict format
                    file_logs = df.to_dict('records')
                    all_logs.extend(file_logs)
                    total_loaded += len(file_logs)
                    print(f"   Loaded {len(file_logs):,} records from {filename}")
            except FileNotFoundError:
                print(f"   Skipped {filename} (file not found)")
                continue
            except Exception as e:
                print(f"   Skipped {filename}: {e}")
                continue
        
        if not all_logs:
            raise FileNotFoundError("No CICIDS files found")
        
        print(f"\n Total loaded: {total_loaded:,} real log records from CICIDS dataset")
        print(f" Processing {len(all_logs):,} logs through stream...")
        
        # Process all logs through the stream efficiently
        batch_size = 1000  # Process in larger batches for efficiency
        processed_count = 0
        
        for i, raw_log in enumerate(all_logs, 1):
            stream.submit_log(raw_log)
            processed_count += 1
            
            # Progress update every batch_size logs
            if i % batch_size == 0:
                print(f"   Processed {i:,}/{len(all_logs):,} logs ({100*i/len(all_logs):.1f}%)...")
                # Small pause to allow queue processing
                time.sleep(0.1)
        
        # Wait for remaining logs to be processed
        print(f"   Waiting for queue to empty...")
        max_wait = 30  # Maximum wait time in seconds
        wait_time = 0
        while stream.queue.qsize() > 0 and wait_time < max_wait:
            time.sleep(0.5)
            wait_time += 0.5
            if wait_time % 5 == 0:
                print(f"   Queue size: {stream.queue.qsize()}, waiting...")
        
        print(f"   Completed processing all {len(all_logs):,} logs")
            
    except FileNotFoundError as e:
        print(f" WARNING: CICIDS data files not found!")
        print(f"   Error: {e}")
        print("   Expected location: data/raw/cicids/*.csv")
        print("   Using minimal test data instead...")
        # Fallback: minimal real-format test data
        test_log = {
            "Flow Start": datetime.now().isoformat(),
            "Src IP": "192.168.1.100",
            "Dst IP": "10.0.0.1",
            "Label": "BENIGN",
            "Protocol": "TCP",
            "Destination Port": 443,
            "Total Length of Fwd Packets": 1000,
            "Total Length of Bwd Packets": 2000,
            "Flow Duration": 1000000
        }
        for i in range(5):
            stream.submit_log(test_log.copy())
            time.sleep(0.1)
    except Exception as e:
        print(f" Error loading CICIDS data: {e}")
        import traceback
        traceback.print_exc()
        print("   Check that data files exist in data/raw/cicids/")
        stream.stop()
        sys.exit(1)

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
