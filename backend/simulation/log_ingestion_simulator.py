"""
Log Ingestion Simulator
Simulates realistic log ingestion from a real system
Generates a mix of benign and attack logs, submitting them through the normal pipeline
"""

import random
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from backend.simulation.threat_simulator import ThreatType, ThreatSimulator


class LogIngestionSimulator:
    """
    Simulates realistic log ingestion from a real system
    
    This creates a more realistic simulation by:
    1. Generating a mix of benign and attack logs
    2. Submitting them through the normal log ingestion pipeline
    3. Letting the system naturally detect threats
    4. Mimicking real-world log flow patterns
    """
    
    def __init__(
        self,
        orchestrator=None,
        on_threat_detected: Optional[Callable] = None,
        benign_log_ratio: float = 0.7  # 70% benign, 30% attacks
    ):
        """
        Initialize log ingestion simulator
        
        Args:
            orchestrator: OrchestratorAgent instance
            on_threat_detected: Callback when threat is detected
            benign_log_ratio: Ratio of benign logs to attack logs (0.0 to 1.0)
        """
        self.orchestrator = orchestrator
        self.on_threat_detected = on_threat_detected
        self.benign_log_ratio = benign_log_ratio
        self.is_running = False
        self.simulation_task = None
        self.threat_simulator = ThreatSimulator(
            orchestrator=orchestrator,
            on_threat_detected=on_threat_detected
        )
        self.config = {
            "logs_per_minute": 10,  # Realistic log rate
            "attack_probability": 1.0 - benign_log_ratio,
            "burst_mode": False,  # Simulate traffic bursts
            "time_variation": True  # Vary log rate over time
        }
        self.generated_logs = []
        self.detected_threats = []
    
    def generate_benign_log(self) -> Dict:
        """Generate a realistic benign log entry"""
        # Common benign activities
        benign_actions = [
            "api_request", "page_view", "data_read", "session_create",
            "file_download", "search_query", "dashboard_access"
        ]
        
        # Internal IPs (more likely to be benign)
        internal_ips = [
            "192.168.1", "10.0.0", "172.16.0"
        ]
        
        ip_base = random.choice(internal_ips)
        ip_octet = random.randint(1, 254)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source_ip": f"{ip_base}.{ip_octet}",
            "destination_ip": "10.0.0.1",
            "user_id": f"USER_{random.randint(1, 100)}",
            "action": random.choice(benign_actions),
            "resource": f"/api/v1/{random.choice(['data', 'users', 'reports'])}",
            "status": "200",
            "protocol": "TCP",
            "port": random.choice([443, 80, 8080]),
            "bytes_sent": random.randint(100, 5000),
            "bytes_received": random.randint(500, 10000),
            "duration": random.uniform(0.1, 2.0),
            "metadata": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "request_count": 1,
                "response_time": random.uniform(50, 200)
            },
            # CICIDS-style fields (benign pattern)
            "Flow Duration": random.uniform(100000, 2000000),  # Normal duration
            "Total Fwd Packets": random.randint(5, 50),
            "Total Backward Packets": random.randint(3, 30),
            "Flow Bytes/s": random.uniform(1000, 10000),
            "Flow Packets/s": random.uniform(1, 10),
            "Destination Port": random.choice([443, 80, 8080]),
            "Fwd Packet Length Mean": random.uniform(500, 1500),
            "Bwd Packet Length Mean": random.uniform(1000, 5000),
            "Flow IAT Mean": random.uniform(0.5, 2.0),  # Normal intervals
            "Fwd IAT Mean": random.uniform(0.3, 1.5),
            "Bwd IAT Mean": random.uniform(0.5, 2.0),
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "FIN Flag Count": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": random.randint(3, 10),
            "Average Packet Size": random.uniform(1000, 3000),
            "Label": "BENIGN"
        }
    
    async def ingest_log(self, log: Dict):
        """
        Ingest a log through the normal pipeline (like a real system)
        
        This mimics what happens when a real system sends logs:
        1. Log is preprocessed
        2. Stored in database
        3. Analyzed for threats
        4. Threat detected if suspicious
        """
        try:
            from backend.utils.database import SecurityLogDatabase
            from backend.utils.preprocessor import LogPreprocessor
            
            db = SecurityLogDatabase()
            preprocessor = LogPreprocessor()
            
            # Process log (like real ingestion)
            processed_log = preprocessor.process_log(log)
            
            # Store in database
            log_id = db.insert_log(processed_log)
            self.generated_logs.append({
                "log_id": log_id,
                "log": processed_log,
                "timestamp": datetime.now()
            })
            
            # If it's an attack log, analyze it
            if log.get("Label") == "ATTACK" or not log.get("Label") == "BENIGN":
                # Analyze through orchestrator (like real detection)
                if self.orchestrator and hasattr(self.orchestrator, 'log_analyzer') and self.orchestrator.log_analyzer.is_trained:
                    try:
                        result = self.orchestrator.analyze_log(log, return_full_analysis=True)
                        if result.get("threat_detected"):
                            self.detected_threats.append(result)
                            if self.on_threat_detected:
                                await self.on_threat_detected(result)
                    except Exception as e:
                        print(f"  Error analyzing log: {e}")
            
            return log_id
            
        except Exception as e:
            print(f"  Error ingesting log: {e}")
            return None
    
    async def simulate_realistic_traffic(self, duration_minutes: int = 5):
        """
        Simulate realistic traffic flow with mix of benign and attack logs
        
        Args:
            duration_minutes: Duration of simulation
        """
        if self.is_running:
            return
        
        self.is_running = True
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        logs_per_minute = self.config["logs_per_minute"]
        log_interval = 60.0 / logs_per_minute  # Seconds between logs
        
        async def _traffic_loop():
            threat_types = list(ThreatType)
            threat_index = 0
            
            while datetime.now() < end_time and self.is_running:
                # Decide if this log is an attack or benign
                is_attack = random.random() < self.config["attack_probability"]
                
                if is_attack and threat_index < len(threat_types):
                    # Generate attack log using threat simulator
                    threat_type = threat_types[threat_index % len(threat_types)]
                    attack_log = self.threat_simulator.generate_threat_log(threat_type)
                    await self.ingest_log(attack_log)
                    threat_index += 1
                else:
                    # Generate benign log
                    benign_log = self.generate_benign_log()
                    await self.ingest_log(benign_log)
                
                # Wait for next log (with some variation)
                wait_time = log_interval * random.uniform(0.8, 1.2)
                await asyncio.sleep(wait_time)
            
            self.is_running = False
        
        self.simulation_task = asyncio.create_task(_traffic_loop())
    
    async def stop(self):
        """Stop log ingestion simulation"""
        self.is_running = False
        if self.simulation_task:
            self.simulation_task.cancel()
            try:
                await self.simulation_task
            except asyncio.CancelledError:
                pass
    
    def get_stats(self) -> Dict:
        """Get simulation statistics"""
        return {
            "is_running": self.is_running,
            "total_logs_generated": len(self.generated_logs),
            "threats_detected": len(self.detected_threats),
            "benign_logs": sum(1 for log in self.generated_logs if log.get("log", {}).get("Label") == "BENIGN"),
            "attack_logs": sum(1 for log in self.generated_logs if log.get("log", {}).get("Label") == "ATTACK")
        }


