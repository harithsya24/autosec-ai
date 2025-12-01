"""
Threat Simulator Engine
Generates realistic security threats for demo purposes
"""

import random
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from enum import Enum
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))


class ThreatType(Enum):
    """Threat type categories"""
    CREDENTIAL_STUFFING = "credential_stuffing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_LOGIN = "suspicious_login"
    API_ABUSE = "api_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    DDoS = "ddos"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionTier(Enum):
    """Action tier classification"""
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


class ThreatSimulator:
    """
    Simulates realistic security threats for demo purposes
    """
    
    # Threat templates with realistic attributes
    THREAT_TEMPLATES = {
        ThreatType.CREDENTIAL_STUFFING: {
            "severity": ThreatSeverity.HIGH,
            "confidence_range": (0.85, 0.95),
            "anomaly_score_range": (0.75, 0.92),
            "mitre_techniques": ["T1078", "T1110"],
            "action_tier": ActionTier.RED,
            "description_template": "Multiple failed login attempts from {source_ip} targeting user accounts",
            "ip_ranges": ["203.45.67", "198.51.100", "192.0.2"],
            "ports": [22, 443, 80, 3389],
            "users": ["admin", "root", "service", "api_user"]
        },
        ThreatType.PRIVILEGE_ESCALATION: {
            "severity": ThreatSeverity.CRITICAL,
            "confidence_range": (0.90, 0.98),
            "anomaly_score_range": (0.88, 0.98),
            "mitre_techniques": ["T1548", "T1055", "T1068"],
            "action_tier": ActionTier.RED,
            "description_template": "Privilege escalation attempt detected from {source_ip} by user {user_id}",
            "ip_ranges": ["10.0.0", "172.16.0", "192.168.1"],
            "ports": [22, 443, 8080],
            "users": ["USER_A", "USER_B", "service_account"]
        },
        ThreatType.SUSPICIOUS_LOGIN: {
            "severity": ThreatSeverity.MEDIUM,
            "confidence_range": (0.70, 0.85),
            "anomaly_score_range": (0.60, 0.80),
            "mitre_techniques": ["T1078", "T1021"],
            "action_tier": ActionTier.YELLOW,
            "description_template": "Suspicious login activity from {source_ip} at unusual time",
            "ip_ranges": ["203.0.113", "198.18.0", "172.217"],
            "ports": [443, 22, 3389],
            "users": ["USER_C", "USER_D", "guest"]
        },
        ThreatType.API_ABUSE: {
            "severity": ThreatSeverity.MEDIUM,
            "confidence_range": (0.65, 0.80),
            "anomaly_score_range": (0.55, 0.75),
            "mitre_techniques": ["T1071", "T1499"],
            "action_tier": ActionTier.YELLOW,
            "description_template": "API abuse detected: {source_ip} making excessive requests to {resource}",
            "ip_ranges": ["104.16", "151.101", "172.64"],
            "ports": [443, 80, 8080],
            "users": ["api_client", "bot_user", "anonymous"]
        },
        ThreatType.DATA_EXFILTRATION: {
            "severity": ThreatSeverity.HIGH,
            "confidence_range": (0.80, 0.92),
            "anomaly_score_range": (0.75, 0.90),
            "mitre_techniques": ["T1041", "T1020", "T1030"],
            "action_tier": ActionTier.RED,
            "description_template": "Potential data exfiltration detected: {source_ip} transferring large volumes of data",
            "ip_ranges": ["185.199.108", "140.82.112", "13.107.42"],
            "ports": [443, 80, 21],
            "users": ["USER_E", "backup_user", "sync_service"]
        },
        ThreatType.BRUTE_FORCE: {
            "severity": ThreatSeverity.LOW,
            "confidence_range": (0.60, 0.75),
            "anomaly_score_range": (0.50, 0.70),
            "mitre_techniques": ["T1110", "T1021"],
            "action_tier": ActionTier.GREEN,
            "description_template": "Brute force attack detected from {source_ip} on port {port}",
            "ip_ranges": ["45.33.32", "192.241.238", "104.248"],
            "ports": [22, 3389, 3306, 5432],
            "users": ["admin", "root", "test"]
        },
        ThreatType.PORT_SCAN: {
            "severity": ThreatSeverity.LOW,
            "confidence_range": (0.55, 0.70),
            "anomaly_score_range": (0.45, 0.65),
            "mitre_techniques": ["T1046", "T1040"],
            "action_tier": ActionTier.GREEN,
            "description_template": "Port scanning activity detected from {source_ip}",
            "ip_ranges": ["185.220.100", "45.146.164", "103.27.124"],
            "ports": [22, 80, 443, 8080, 3306],
            "users": ["scanner", "probe", "unknown"]
        },
        ThreatType.DDoS: {
            "severity": ThreatSeverity.HIGH,
            "confidence_range": (0.75, 0.88),
            "anomaly_score_range": (0.70, 0.85),
            "mitre_techniques": ["T1498", "T1499"],
            "action_tier": ActionTier.RED,
            "description_template": "DDoS attack detected: {source_ip} flooding {resource}",
            "ip_ranges": ["172.217", "104.16", "151.101"],
            "ports": [80, 443],
            "users": ["attacker", "botnet", "unknown"]
        },
        ThreatType.MALWARE: {
            "severity": ThreatSeverity.HIGH,
            "confidence_range": (0.78, 0.90),
            "anomaly_score_range": (0.72, 0.88),
            "mitre_techniques": ["T1059", "T1204", "T1566"],
            "action_tier": ActionTier.RED,
            "description_template": "Malware activity detected from {source_ip} accessing {resource}",
            "ip_ranges": ["185.220.100", "45.146.164", "103.27.124"],
            "ports": [443, 80, 8080],
            "users": ["compromised_user", "infected_host", "malware"]
        },
        ThreatType.INSIDER_THREAT: {
            "severity": ThreatSeverity.CRITICAL,
            "confidence_range": (0.88, 0.96),
            "anomaly_score_range": (0.85, 0.95),
            "mitre_techniques": ["T1078", "T1048", "T1021"],
            "action_tier": ActionTier.RED,
            "description_template": "Insider threat detected: {user_id} accessing unauthorized resources",
            "ip_ranges": ["10.0.0", "172.16.0", "192.168.1"],
            "ports": [443, 22, 3389],
            "users": ["USER_F", "employee_123", "contractor_45"]
        }
    }
    
    def __init__(self, orchestrator=None, on_threat_detected: Optional[Callable] = None):
        """
        Initialize threat simulator
        
        Args:
            orchestrator: OrchestratorAgent instance for processing threats
            on_threat_detected: Callback function when threat is detected
        """
        self.orchestrator = orchestrator
        self.on_threat_detected = on_threat_detected
        self.is_running = False
        self.simulation_task = None
        self.config = {
            "interval_seconds": 45,  # Default: threat every 45 seconds
            "enabled_threats": list(ThreatType),  # All threats enabled by default
            "auto_clear_low_priority": False,
            "clear_after_seconds": 120
        }
        self.generated_threats = []
        self.demo_mode = False
        self.demo_threats_plan = []
        self.demo_start_time = None
    
    def generate_threat_log(self, threat_type: ThreatType) -> Dict:
        """
        Generate a realistic log entry for a specific threat type
        
        Args:
            threat_type: Type of threat to simulate
            
        Returns:
            Dictionary representing a log entry that will trigger detection
        """
        template = self.THREAT_TEMPLATES[threat_type]
        
        # Generate random IP from template ranges
        ip_base = random.choice(template["ip_ranges"])
        ip_octet = random.randint(1, 254)
        source_ip = f"{ip_base}.{ip_octet}"
        
        # Generate random user
        user_id = random.choice(template["users"])
        
        # Generate random port
        port = random.choice(template["ports"])
        
        # Generate resource based on threat type
        resources = {
            ThreatType.CREDENTIAL_STUFFING: "/api/v1/auth/login",
            ThreatType.PRIVILEGE_ESCALATION: "/api/v1/admin/escalate",
            ThreatType.SUSPICIOUS_LOGIN: "/api/v1/auth/session",
            ThreatType.API_ABUSE: "/api/v1/data/export",
            ThreatType.DATA_EXFILTRATION: "/api/v1/database/backup",
            ThreatType.BRUTE_FORCE: f"/ssh/{user_id}",
            ThreatType.PORT_SCAN: f"/scan/{port}",
            ThreatType.DDoS: "/api/v1/public/endpoint",
            ThreatType.MALWARE: "/api/v1/upload/executable",
            ThreatType.INSIDER_THREAT: "/api/v1/confidential/data"
        }
        resource = resources.get(threat_type, "/api/v1/unknown")
        
        # Generate realistic log attributes based on threat type
        base_log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "destination_ip": "10.0.0.1",  # Internal server
            "user_id": user_id,
            "action": self._get_action_for_threat(threat_type),
            "resource": resource,
            "status": self._get_status_for_threat(threat_type),
            "protocol": "TCP",
            "port": port,
            "bytes_sent": self._get_bytes_for_threat(threat_type, "sent"),
            "bytes_received": self._get_bytes_for_threat(threat_type, "received"),
            "duration": self._get_duration_for_threat(threat_type),
            "metadata": {
                "user_agent": self._get_user_agent_for_threat(threat_type),
                "request_count": self._get_request_count_for_threat(threat_type),
                "response_time": random.uniform(50, 500)
            }
        }
        
        # Add CICIDS-style fields for ML detection
        base_log.update({
            "Flow Duration": base_log["duration"] * 1000,  # Convert to milliseconds
            "Total Fwd Packets": random.randint(10, 1000),
            "Total Backward Packets": random.randint(5, 500),
            "Flow Bytes/s": base_log["bytes_sent"] / max(base_log["duration"], 0.1),
            "Flow Packets/s": random.uniform(10, 200),
            "Destination Port": port,
            "Fwd Packet Length Mean": base_log["bytes_sent"] / max(random.randint(10, 100), 1),
            "Bwd Packet Length Mean": base_log["bytes_received"] / max(random.randint(5, 50), 1),
            "Flow IAT Mean": random.uniform(0.1, 2.0),
            "Fwd IAT Mean": random.uniform(0.1, 1.5),
            "Bwd IAT Mean": random.uniform(0.1, 2.0),
            "Fwd PSH Flags": random.randint(0, 1),
            "Bwd PSH Flags": random.randint(0, 1),
            "FIN Flag Count": random.randint(0, 2),
            "SYN Flag Count": random.randint(1, 3),
            "RST Flag Count": random.randint(0, 1),
            "ACK Flag Count": random.randint(5, 20),
            "Average Packet Size": (base_log["bytes_sent"] + base_log["bytes_received"]) / max(random.randint(10, 100), 1),
            "Label": "ATTACK"  # This will trigger detection
        })
        
        return base_log
    
    def _get_action_for_threat(self, threat_type: ThreatType) -> str:
        """Get appropriate action string for threat type"""
        actions = {
            ThreatType.CREDENTIAL_STUFFING: "login_attempt",
            ThreatType.PRIVILEGE_ESCALATION: "privilege_escalation",
            ThreatType.SUSPICIOUS_LOGIN: "session_create",
            ThreatType.API_ABUSE: "api_request",
            ThreatType.DATA_EXFILTRATION: "data_export",
            ThreatType.BRUTE_FORCE: "authentication",
            ThreatType.PORT_SCAN: "connection_attempt",
            ThreatType.DDoS: "http_request",
            ThreatType.MALWARE: "file_upload",
            ThreatType.INSIDER_THREAT: "data_access"
        }
        return actions.get(threat_type, "unknown")
    
    def _get_status_for_threat(self, threat_type: ThreatType) -> str:
        """Get appropriate status for threat type"""
        if threat_type in [ThreatType.CREDENTIAL_STUFFING, ThreatType.BRUTE_FORCE]:
            return "401"  # Unauthorized
        elif threat_type in [ThreatType.PRIVILEGE_ESCALATION, ThreatType.INSIDER_THREAT]:
            return "403"  # Forbidden
        elif threat_type == ThreatType.API_ABUSE:
            return "429"  # Too Many Requests
        elif threat_type == ThreatType.DDoS:
            return "503"  # Service Unavailable
        else:
            return "200"  # OK (but suspicious)
    
    def _get_bytes_for_threat(self, threat_type: ThreatType, direction: str) -> int:
        """Get realistic byte counts for threat type"""
        if threat_type == ThreatType.DATA_EXFILTRATION:
            return random.randint(10000000, 100000000)  # 10MB - 100MB
        elif threat_type == ThreatType.DDoS:
            return random.randint(1000, 10000)  # Small packets, many of them
        elif threat_type == ThreatType.API_ABUSE:
            return random.randint(5000, 50000)
        elif direction == "sent":
            return random.randint(100, 5000)
        else:
            return random.randint(500, 10000)
    
    def _get_duration_for_threat(self, threat_type: ThreatType) -> float:
        """Get realistic duration for threat type"""
        if threat_type == ThreatType.DATA_EXFILTRATION:
            return random.uniform(30.0, 300.0)  # Long transfer
        elif threat_type == ThreatType.BRUTE_FORCE:
            return random.uniform(0.1, 1.0)  # Quick attempts
        elif threat_type == ThreatType.DDoS:
            return random.uniform(0.05, 0.5)  # Very quick
        else:
            return random.uniform(1.0, 10.0)
    
    def _get_user_agent_for_threat(self, threat_type: ThreatType) -> str:
        """Get realistic user agent for threat type"""
        user_agents = {
            ThreatType.CREDENTIAL_STUFFING: "python-requests/2.28.0",
            ThreatType.API_ABUSE: "curl/7.68.0",
            ThreatType.BRUTE_FORCE: "Hydra/9.0",
            ThreatType.MALWARE: "Mozilla/5.0 (compatible; malware)",
            ThreatType.DDoS: "bot/1.0"
        }
        return user_agents.get(threat_type, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    
    def _get_request_count_for_threat(self, threat_type: ThreatType) -> int:
        """Get realistic request count for threat type"""
        if threat_type == ThreatType.API_ABUSE:
            return random.randint(100, 1000)
        elif threat_type == ThreatType.DDoS:
            return random.randint(1000, 10000)
        elif threat_type == ThreatType.BRUTE_FORCE:
            return random.randint(50, 200)
        else:
            return random.randint(1, 10)
    
    def _generate_threat_explanation(self, threat_type: ThreatType, threat_log: Dict, template: Dict) -> str:
        """Generate detailed threat explanation"""
        explanations = {
            ThreatType.CREDENTIAL_STUFFING: f"Multiple failed login attempts detected from {threat_log.get('source_ip')} targeting user accounts. This indicates a credential stuffing attack where attackers use stolen credentials to gain unauthorized access.",
            ThreatType.PRIVILEGE_ESCALATION: f"Privilege escalation attempt detected from {threat_log.get('source_ip')} by user {threat_log.get('user_id')}. The user attempted to access administrative resources without proper authorization.",
            ThreatType.SUSPICIOUS_LOGIN: f"Suspicious login activity detected from {threat_log.get('source_ip')} at an unusual time. The login pattern deviates from normal user behavior.",
            ThreatType.API_ABUSE: f"API abuse detected: {threat_log.get('source_ip')} is making excessive requests to {threat_log.get('resource')}. This may indicate automated scraping or DDoS preparation.",
            ThreatType.DATA_EXFILTRATION: f"Potential data exfiltration detected: {threat_log.get('source_ip')} is transferring large volumes of data ({threat_log.get('bytes_sent', 0):,} bytes) to external destination.",
            ThreatType.BRUTE_FORCE: f"Brute force attack detected from {threat_log.get('source_ip')} on port {threat_log.get('port')}. Multiple failed authentication attempts indicate password guessing attack.",
            ThreatType.PORT_SCAN: f"Port scanning activity detected from {threat_log.get('source_ip')}. The source is probing multiple ports, indicating reconnaissance activity.",
            ThreatType.DDoS: f"DDoS attack detected: {threat_log.get('source_ip')} is flooding {threat_log.get('resource')} with requests, attempting to overwhelm the service.",
            ThreatType.MALWARE: f"Malware activity detected from {threat_log.get('source_ip')} accessing {threat_log.get('resource')}. The traffic pattern matches known malware communication signatures.",
            ThreatType.INSIDER_THREAT: f"Insider threat detected: {threat_log.get('user_id')} is accessing unauthorized resources from {threat_log.get('source_ip')}. This may indicate compromised credentials or malicious insider activity."
        }
        return explanations.get(threat_type, f"Security threat detected: {threat_type.value.replace('_', ' ')}")
    
    def _get_mitre_description(self, technique_id: str) -> str:
        """Get MITRE ATT&CK technique description"""
        descriptions = {
            "T1078": "Valid Accounts - Adversaries may steal and use credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "T1110": "Brute Force - Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
            "T1548": "Abuse Elevation Control Mechanism - Adversaries may abuse elevation control mechanisms to gain higher-level permissions.",
            "T1055": "Process Injection - Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
            "T1068": "Exploitation for Privilege Escalation - Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
            "T1021": "Remote Services - Adversaries may use valid accounts to log into a service that accepts remote connections.",
            "T1071": "Application Layer Protocol - Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
            "T1499": "Endpoint Denial of Service - Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services.",
            "T1041": "Exfiltration Over C2 Channel - Adversaries may steal data by exfiltrating it over an existing command and control channel.",
            "T1020": "Automated Exfiltration - Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing.",
            "T1030": "Data Transfer Size Limits - Adversaries may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds.",
            "T1046": "Network Service Scanning - Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
            "T1040": "Network Sniffing - Adversaries may passively sniff network traffic to capture information about the target.",
            "T1498": "Network Denial of Service - Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
            "T1059": "Command and Scripting Interpreter - Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
            "T1204": "User Execution - Adversaries may rely upon specific actions by a user in order to gain execution.",
            "T1566": "Phishing - Adversaries may send phishing messages to gain access to victim systems.",
            "T1048": "Exfiltration Over Alternative Protocol - Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel."
        }
        return descriptions.get(technique_id, f"MITRE ATT&CK Technique {technique_id} - Security technique used in this attack.")
    
    def _generate_threat_details(self, threat_type: ThreatType, threat_log: Dict, template: Dict, confidence: float, anomaly_score: float) -> Dict:
        """Generate comprehensive threat details for action management"""
        
        # Generate target system names
        target_systems = {
            ThreatType.INSIDER_THREAT: "Production Database Server (db-prod-01)",
            ThreatType.PRIVILEGE_ESCALATION: "Admin Panel (admin.company.com)",
            ThreatType.CREDENTIAL_STUFFING: "Login API Endpoint (/auth/login)",
            ThreatType.DATA_EXFILTRATION: "File Server (files-prod-01)",
            ThreatType.API_ABUSE: "Application Server (app-prod-02)",
            ThreatType.BRUTE_FORCE: "SSH Service (ssh.company.com)",
            ThreatType.PORT_SCAN: "Network Infrastructure",
            ThreatType.DDoS: "Web Application (web-prod-01)",
            ThreatType.MALWARE: "Application Server (app-prod-02)",
            ThreatType.SUSPICIOUS_LOGIN: "User Portal (portal.company.com)"
        }
        
        # Generate affected resources
        affected_resources = {
            ThreatType.INSIDER_THREAT: "/api/v1/customer-data",
            ThreatType.PRIVILEGE_ESCALATION: "/admin/users",
            ThreatType.CREDENTIAL_STUFFING: "/auth/login",
            ThreatType.DATA_EXFILTRATION: "/api/v1/export",
            ThreatType.API_ABUSE: "/api/v1/data",
            ThreatType.BRUTE_FORCE: "SSH Port 22",
            ThreatType.PORT_SCAN: "Multiple Ports",
            ThreatType.DDoS: "/",
            ThreatType.MALWARE: "/tmp/malicious_binary.exe",
            ThreatType.SUSPICIOUS_LOGIN: "/dashboard"
        }
        
        # Generate attack vectors
        attack_vectors = {
            ThreatType.INSIDER_THREAT: "Privilege escalation via stolen credentials",
            ThreatType.PRIVILEGE_ESCALATION: "Exploited vulnerability CVE-2023-1234",
            ThreatType.CREDENTIAL_STUFFING: f"{random.randint(30, 100)} failed login attempts in {random.randint(60, 180)} seconds",
            ThreatType.DATA_EXFILTRATION: f"Large file transfer ({random.uniform(1.5, 5.0):.1f} GB) to external S3 bucket",
            ThreatType.API_ABUSE: f"Excessive requests ({random.randint(1000, 5000)} requests/min)",
            ThreatType.BRUTE_FORCE: f"{random.randint(50, 200)} failed authentication attempts",
            ThreatType.PORT_SCAN: "Probing multiple ports (reconnaissance activity)",
            ThreatType.DDoS: f"Flooding with {random.randint(10000, 50000)} requests/min",
            ThreatType.MALWARE: "Suspicious process spawned (crypto miner)",
            ThreatType.SUSPICIOUS_LOGIN: "Login from unusual location/time"
        }
        
        # Generate user info
        user_id = threat_log.get("user_id", "USER_UNKNOWN")
        user_email = f"{user_id.lower().replace('_', '.')}@company.com"
        if len(user_id) > 10:
            user_email = f"{user_id[:5]}.***@company.com"
        
        # Generate timeline
        base_time = datetime.now() - timedelta(minutes=random.randint(2, 10))
        timeline = [
            {
                "time": (base_time - timedelta(minutes=4)).strftime("%H:%M:%S"),
                "event": "Normal login from USER_A",
                "status": "normal"
            },
            {
                "time": (base_time - timedelta(minutes=3, seconds=38)).strftime("%H:%M:%S"),
                "event": "Elevated privileges requested (unusual)",
                "status": "warning"
            },
            {
                "time": (base_time - timedelta(minutes=3, seconds=15)).strftime("%H:%M:%S"),
                "event": f"Access to sensitive {threat_type.value.replace('_', ' ')} resources",
                "status": "warning"
            },
            {
                "time": (base_time - timedelta(minutes=2, seconds=50)).strftime("%H:%M:%S"),
                "event": f"Large {threat_type.value.replace('_', ' ')} operation executed ({random.randint(1000, 10000)}+ records)",
                "status": "danger"
            },
            {
                "time": (base_time - timedelta(minutes=2, seconds=30)).strftime("%H:%M:%S"),
                "event": f"THREAT DETECTED - Anomaly score: {abs(anomaly_score):.2f}",
                "status": "critical"
            }
        ]
        
        # Generate risk assessment
        risk_assessments = {
            ThreatType.INSIDER_THREAT: {
                "risk": "Insider with elevated access attempting data exfiltration",
                "data_at_risk": f"{random.randint(10000, 100000)}+ customer records (PII, payment info)",
                "compliance": "Potential violation: GDPR, PCI-DSS",
                "impact": f"${random.randint(1, 5)}M+ if data is leaked"
            },
            ThreatType.PRIVILEGE_ESCALATION: {
                "risk": "Unauthorized privilege escalation detected",
                "data_at_risk": "Full system access, all databases",
                "compliance": "Potential violation: SOC2, ISO 27001",
                "impact": "$5M+ if system is compromised"
            },
            ThreatType.CREDENTIAL_STUFFING: {
                "risk": "Automated credential stuffing attack",
                "data_at_risk": "User account compromise, potential data breach",
                "compliance": "Potential violation: GDPR",
                "impact": "$1M+ if accounts are compromised"
            },
            ThreatType.DATA_EXFILTRATION: {
                "risk": "Large-scale data exfiltration in progress",
                "data_at_risk": f"{random.randint(5000, 50000)}+ records being transferred",
                "compliance": "Critical violation: GDPR, PCI-DSS",
                "impact": f"${random.randint(2, 10)}M+ if data is leaked"
            },
            ThreatType.API_ABUSE: {
                "risk": "API abuse causing service degradation",
                "data_at_risk": "Service availability, potential DDoS",
                "compliance": "SLA violation risk",
                "impact": "$500K+ in service disruption"
            },
            ThreatType.BRUTE_FORCE: {
                "risk": "Brute force attack on authentication service",
                "data_at_risk": "User account compromise",
                "compliance": "Potential violation: GDPR",
                "impact": "$500K+ if accounts are compromised"
            },
            ThreatType.PORT_SCAN: {
                "risk": "Reconnaissance activity - potential pre-attack",
                "data_at_risk": "Network topology exposure",
                "compliance": "Low risk",
                "impact": "$100K+ if leads to successful attack"
            },
            ThreatType.DDoS: {
                "risk": "Distributed Denial of Service attack",
                "data_at_risk": "Service availability",
                "compliance": "SLA violation",
                "impact": "$1M+ in service disruption"
            },
            ThreatType.MALWARE: {
                "risk": "Malware execution detected",
                "data_at_risk": "System compromise, data theft",
                "compliance": "Critical violation: SOC2",
                "impact": "$2M+ if system is compromised"
            },
            ThreatType.SUSPICIOUS_LOGIN: {
                "risk": "Suspicious login from unusual location",
                "data_at_risk": "User account compromise",
                "compliance": "Potential violation: GDPR",
                "impact": "$500K+ if account is compromised"
            }
        }
        
        risk = risk_assessments.get(threat_type, {
            "risk": "Security threat detected",
            "data_at_risk": "Unknown",
            "compliance": "Unknown",
            "impact": "Unknown"
        })
        
        # Generate AI reasoning
        ai_reasoning = f"Pattern matches known {threat_type.value.replace('_', ' ')} behavior: {attack_vectors[threat_type]}. Similar to past incident #{random.randint(1000, 9999)} where similar attack pattern was observed. Confidence: {confidence:.1%} based on anomaly score {abs(anomaly_score):.2f} and RAG context similarity {random.uniform(0.75, 0.95):.2f}."
        
        # Generate evidence/logs
        evidence = {
            "raw_log": {
                "timestamp": threat_log.get("timestamp", datetime.now().isoformat()),
                "user_id": user_id,
                "action": threat_log.get("action", "unknown"),
                "resource": threat_log.get("resource", "unknown"),
                "ip": threat_log.get("source_ip", "unknown"),
                "anomaly_score": f"{abs(anomaly_score):.3f}",
                "session_duration": f"{random.randint(100, 500)}s"
            },
            "anomaly_detection": {
                "query_volume": f"{random.randint(200, 600)}% above user baseline",
                "access_time": "Outside normal hours" if random.choice([True, False]) else "Normal hours",
                "data_scope": f"{random.randint(5, 20)}x larger than typical operation"
            }
        }
        
        return {
            "threat_type": threat_type.value.replace("_", " ").title(),
            "severity": template["severity"].value,
            "confidence": confidence,
            "mitre_technique": template["mitre_techniques"][0] if template["mitre_techniques"] else "Unknown",
            "target_system": target_systems.get(threat_type, "Unknown System"),
            "affected_resource": affected_resources.get(threat_type, threat_log.get("resource", "Unknown")),
            "affected_user": user_id,
            "user_email": user_email,
            "source_ip": threat_log.get("source_ip", "Unknown"),
            "attack_vector": attack_vectors.get(threat_type, "Unknown attack vector"),
            "timeline": timeline,
            "risk_assessment": risk,
            "ai_reasoning": ai_reasoning,
            "evidence": evidence,
            "detected_at": threat_log.get("timestamp", datetime.now().isoformat())
        }
    
    async def simulate_threat(self, threat_type: ThreatType) -> Dict:
        """
        Simulate a single threat - simplified direct approach
        
        This creates threat records directly using threat templates.
        Works reliably without requiring orchestrator to be trained.
        
        Args:
            threat_type: Type of threat to simulate
            
        Returns:
            Complete threat analysis result
        """
        # Generate threat log for metadata (IP, user, resource, etc.)
        threat_log = self.generate_threat_log(threat_type)
        template = self.THREAT_TEMPLATES[threat_type]
        
        # Use direct threat generation (always works, doesn't depend on ML)
        return await self._force_threat_detection(threat_log, threat_type, template)
    
    async def _force_threat_detection(self, threat_log: Dict, threat_type: ThreatType, template: Dict) -> Dict:
        """Force threat detection with template values if ML doesn't detect it"""
        confidence = random.uniform(*template["confidence_range"])
        anomaly_score = -random.uniform(*template["anomaly_score_range"])
        
        # Determine pending actions based on action tier
        executed_actions = []
        pending_actions = []
        
        action_tier = template["action_tier"]
        
        # Generate detailed threat information
        threat_details = self._generate_threat_details(threat_type, threat_log, template, confidence, anomaly_score)
        
        action = {
            "action_id": f"action_{datetime.now().timestamp()}",
            "type": "block_ip" if action_tier != ActionTier.GREEN else "log_only",
            "tier": action_tier.value,
            "description": f"Recommended action for {threat_type.value.replace('_', ' ')}",
            "parameters": {"source_ip": threat_log["source_ip"]},
            "requires_approval": action_tier == ActionTier.RED,
            # Add rich threat context to action
            "threat_context": threat_details
        }
        
        if action_tier == ActionTier.GREEN:
            executed_actions.append({**action, "status": "completed"})
        elif action_tier == ActionTier.YELLOW:
            # Yellow actions may auto-execute
            executed_actions.append({**action, "status": "completed", "auto_execute": True})
        else:  # RED
            pending_actions.append({**action, "status": "pending"})
        
        result = {
            "threat_detected": True,
            "status": "threat_identified",
            "anomaly": {
                "anomaly_score": anomaly_score,
                "severity": template["severity"].value,
                "detection_method": "simulation",
                "source_ip": threat_log["source_ip"],
                "user_id": threat_log["user_id"],
                "action": threat_log["action"],
                "resource": threat_log["resource"],
                "status": threat_log["status"],
                "timestamp": threat_log.get("timestamp", datetime.now().isoformat())
            },
            "threat_analysis": {
                "threat_type": threat_type.value.replace("_", " ").title(),
                "confidence": confidence,
                "severity": template["severity"].value,
                "explanation": self._generate_threat_explanation(threat_type, threat_log, template),
                "matched_techniques": template["mitre_techniques"],
                "recommendations": [],
                # Add reasoning chain for detail page
                "reasoning_chain": [
                    {
                        "step": 1,
                        "name": "Anomaly Detection",
                        "description": "ML model detected anomalous patterns in network traffic",
                        "model": "Isolation Forest",
                        "result": f"Anomaly score: {anomaly_score:.3f} (threshold: -0.5)",
                        "duration_ms": random.randint(50, 150)
                    },
                    {
                        "step": 2,
                        "name": "Threat Classification",
                        "description": "Classified threat type based on attack patterns",
                        "model": "Rule-based + Template Matching",
                        "result": f"Identified as {threat_type.value.replace('_', ' ')} with {confidence:.1%} confidence",
                        "duration_ms": random.randint(20, 80)
                    },
                    {
                        "step": 3,
                        "name": "MITRE ATT&CK Mapping",
                        "description": "Matched attack patterns to MITRE ATT&CK framework",
                        "model": "Vector Search (RAG)",
                        "result": f"Matched techniques: {', '.join(template['mitre_techniques'])}",
                        "duration_ms": random.randint(100, 300)
                    },
                    {
                        "step": 4,
                        "name": "Action Recommendation",
                        "description": "Generated mitigation actions based on threat severity",
                        "model": "Response Agent",
                        "result": f"Recommended {action_tier.value.upper()} tier action: {action.get('description', 'Mitigation action')}",
                        "duration_ms": random.randint(30, 100)
                    }
                ],
                # Add retrieved context for detail page
                "retrieved_context": [
                    {
                        "id": f"mitre_{tech}",
                        "title": f"MITRE ATT&CK Technique {tech}",
                        "description": self._get_mitre_description(tech),
                        "source": f"https://attack.mitre.org/techniques/{tech.replace('T', '')}",
                        "similarity": random.uniform(0.75, 0.95),
                        "type": "mitre"
                    }
                    for tech in template["mitre_techniques"][:3]  # Limit to 3 for display
                ],
                # Add confidence breakdown for detail page
                "confidence_breakdown": {
                    "anomaly_score": abs(anomaly_score),
                    "rag_quality": random.uniform(0.70, 0.90),
                    "source_diversity": random.uniform(0.60, 0.85),
                    "quality_distribution": random.uniform(0.65, 0.88),
                    "overall": confidence
                }
            },
            "recommended_actions": {
                "summary": {
                    "total_actions": 1,
                    "green": 1 if action_tier == ActionTier.GREEN else 0,
                    "yellow": 1 if action_tier == ActionTier.YELLOW else 0,
                    "red": 1 if action_tier == ActionTier.RED else 0
                },
                "actions": {
                    action_tier.value: [action]
                }
            },
            "executed_actions": executed_actions,
            "pending_actions": pending_actions,
            "simulation_metadata": {
                "threat_type": threat_type.value,
                "template_severity": template["severity"].value,
                "template_confidence_range": template["confidence_range"],
                "mitre_techniques": template["mitre_techniques"],
                "action_tier": action_tier.value,
                "simulated_at": datetime.now().isoformat(),
                "ingestion_method": "template_based"
            },
            "analyzed_at": datetime.now().isoformat()
        }
        
        # Always call callback to save to DB and broadcast
        if self.on_threat_detected:
            try:
                await self.on_threat_detected(result)
                print(f"  ✓ Threat saved and broadcast: {threat_type.value.replace('_', ' ').title()} (severity: {template['severity'].value}, confidence: {confidence:.2%})")
            except Exception as e:
                print(f"  ✗ Error in threat callback: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"  ⚠ No callback set - threat not saved")
        
        self.generated_threats.append(result)
        return result
    
    async def start_continuous_simulation(self):
        """Start continuous threat simulation"""
        if self.is_running:
            return
        
        self.is_running = True
        
        async def _simulation_loop():
            while self.is_running:
                # Select random threat type from enabled threats
                threat_type = random.choice(self.config["enabled_threats"])
                
                # Simulate threat
                print(f"\n📥 Continuous mode: Generating threat - {threat_type.value.replace('_', ' ').title()}")
                try:
                    result = await self.simulate_threat(threat_type)
                    if result.get("threat_detected"):
                        print(f"   ✓ Threat generated")
                except Exception as e:
                    print(f"   ✗ Error: {e}")
                    import traceback
                    traceback.print_exc()
                
                # Wait for next interval
                await asyncio.sleep(self.config["interval_seconds"])
        
        self.simulation_task = asyncio.create_task(_simulation_loop())
    
    async def start_demo_mode(self, duration_minutes: int = 5):
        """
        Start demo mode with pre-planned threats
        
        Args:
            duration_minutes: Duration of demo in minutes
        """
        if self.is_running:
            return
        
        # Plan demo threats: 2 CRITICAL, 3 HIGH, 3 MEDIUM, 2 LOW
        self.demo_threats_plan = [
            (0, ThreatType.PRIVILEGE_ESCALATION),  # CRITICAL
            (30, ThreatType.INSIDER_THREAT),  # CRITICAL
            (60, ThreatType.CREDENTIAL_STUFFING),  # HIGH
            (90, ThreatType.DATA_EXFILTRATION),  # HIGH
            (120, ThreatType.DDoS),  # HIGH
            (150, ThreatType.SUSPICIOUS_LOGIN),  # MEDIUM
            (180, ThreatType.API_ABUSE),  # MEDIUM
            (210, ThreatType.MALWARE),  # MEDIUM
            (240, ThreatType.BRUTE_FORCE),  # LOW
            (270, ThreatType.PORT_SCAN),  # LOW
        ]
        
        self.demo_mode = True
        self.demo_start_time = datetime.now()
        self.is_running = True
        
        async def _demo_loop():
            start_time = datetime.now()
            end_time = start_time + timedelta(minutes=duration_minutes)
            
            for delay_seconds, threat_type in self.demo_threats_plan:
                if not self.is_running:
                    break
                
                # Wait until it's time for this threat
                elapsed = (datetime.now() - start_time).total_seconds()
                wait_time = max(0, delay_seconds - elapsed)
                
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                
                if datetime.now() >= end_time:
                    break
                
                # Simulate threat
                await self.simulate_threat(threat_type)
            
            # Wait until demo duration is complete
            remaining_time = (end_time - datetime.now()).total_seconds()
            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
            
            self.is_running = False
            self.demo_mode = False
        
        self.simulation_task = asyncio.create_task(_demo_loop())
    
    async def stop_simulation(self):
        """Stop threat simulation"""
        self.is_running = False
        if self.simulation_task:
            self.simulation_task.cancel()
            try:
                await self.simulation_task
            except asyncio.CancelledError:
                pass
        self.demo_mode = False
    
    def get_status(self) -> Dict:
        """Get simulation status"""
        return {
            "is_running": self.is_running,
            "demo_mode": self.demo_mode,
            "config": self.config,
            "threats_generated": len(self.generated_threats),
            "demo_start_time": self.demo_start_time.isoformat() if self.demo_start_time else None
        }
    
    def update_config(self, **kwargs):
        """Update simulation configuration"""
        self.config.update(kwargs)
    
    async def generate_next_threat(self) -> Dict:
        """Generate next threat immediately (for manual trigger)"""
        threat_type = random.choice(self.config["enabled_threats"])
        return await self.simulate_threat(threat_type)

