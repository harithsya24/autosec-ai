"""
AutoSec AI - Unified Log Schema
Defines standard format for security logs across different sources
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class LogSource(str, Enum):
    """Source of the log entry"""
    CICIDS = "cicids"
    CLOUDTRAIL = "cloudtrail"
    SYSTEM = "system"
    CUSTOM = "custom"


class ThreatLevel(str, Enum):
    """Threat severity level"""
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityLog(BaseModel):
    """
    Unified security log format
    Standard schema for all log types
    """
    
    # Core identifiers
    log_id: str = Field(..., description="Unique log identifier")
    timestamp: datetime = Field(..., description="When the event occurred")
    source: LogSource = Field(..., description="Source system")
    
    # Network information
    source_ip: Optional[str] = Field(None, description="Source IP address (anonymized)")
    destination_ip: Optional[str] = Field(None, description="Destination IP")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Network protocol (TCP/UDP/etc)")
    
    # User/Identity
    user_id: Optional[str] = Field(None, description="User identifier (anonymized)")
    user_role: Optional[str] = Field(None, description="User role/permission level")
    
    # Action/Event
    action: str = Field(..., description="Action performed (login/api_call/file_access)")
    resource: Optional[str] = Field(None, description="Target resource")
    status: str = Field(..., description="Result status (success/failed/denied)")
    
    # Flow characteristics (from CICIDS)
    flow_duration: Optional[float] = Field(None, description="Duration of network flow")
    total_packets: Optional[int] = Field(None, description="Total packets in flow")
    total_bytes: Optional[int] = Field(None, description="Total bytes transferred")
    packets_per_second: Optional[float] = Field(None, description="Packet rate")
    bytes_per_second: Optional[float] = Field(None, description="Byte rate")
    
    # Flags and indicators
    flags: Optional[Dict[str, int]] = Field(None, description="TCP flags (SYN, ACK, etc)")
    
    # Threat classification
    threat_level: ThreatLevel = Field(ThreatLevel.BENIGN, description="Threat severity")
    threat_type: Optional[str] = Field(None, description="Type of threat (FTP-Patator, DDoS)")
    is_attack: bool = Field(False, description="Whether this is an attack")
    
    # ML/Analysis
    anomaly_score: Optional[float] = Field(None, description="Anomaly score from ML model (0-1)")
    confidence: Optional[float] = Field(None, description="Classification confidence (0-1)")
    
    # Additional context
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional data")
    
    class Config:
        json_schema_extra = {
            "example": {
                "log_id": "log_20241113_001",
                "timestamp": "2024-11-13T10:30:00Z",
                "source": "cicids",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "destination_port": 22,
                "protocol": "TCP",
                "user_id": "user_123",
                "action": "ssh_login",
                "resource": "/admin",
                "status": "failed",
                "flow_duration": 120.5,
                "total_packets": 150,
                "threat_level": "medium",
                "threat_type": "SSH-Patator",
                "is_attack": True,
                "anomaly_score": 0.85
            }
        }


class CICIDSToUnified:
    """Convert CICIDS format to unified schema"""
    
    @staticmethod
    def convert(cicids_row: Dict, log_id: str) -> SecurityLog:
        """
        Convert a CICIDS row to unified schema
        
        Args:
            cicids_row: Dictionary from CICIDS DataFrame row
            log_id: Unique identifier for this log
        
        Returns:
            SecurityLog object
        """
        
        # Determine threat level from label
        label = cicids_row.get('Label', 'BENIGN')
        is_attack = label != 'BENIGN'
        
        if label == 'BENIGN':
            threat_level = ThreatLevel.BENIGN
        elif 'DDoS' in label or 'DoS' in label:
            threat_level = ThreatLevel.CRITICAL
        elif 'Patator' in label or 'Brute Force' in label:
            threat_level = ThreatLevel.HIGH
        elif 'PortScan' in label:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        # Extract flags
        flags = {
            'FIN': int(cicids_row.get('FIN Flag Count', 0)),
            'SYN': int(cicids_row.get('SYN Flag Count', 0)),
            'RST': int(cicids_row.get('RST Flag Count', 0)),
            'PSH': int(cicids_row.get('PSH Flag Count', 0)),
            'ACK': int(cicids_row.get('ACK Flag Count', 0)),
            'URG': int(cicids_row.get('URG Flag Count', 0))
        }
        
        return SecurityLog(
            log_id=log_id,
            timestamp=datetime.now(),  # CICIDS doesn't have timestamps, use current
            source=LogSource.CICIDS,
            destination_port=int(cicids_row.get('Destination Port', 0)),
            protocol="TCP",  # CICIDS is mostly TCP
            action="network_flow",
            resource=f"port_{cicids_row.get('Destination Port', 0)}",
            status="success" if not is_attack else "suspicious",
            flow_duration=float(cicids_row.get('Flow Duration', 0)),
            total_packets=int(
                cicids_row.get('Total Fwd Packets', 0) + 
                cicids_row.get('Total Backward Packets', 0)
            ),
            total_bytes=int(
                cicids_row.get('Total Length of Fwd Packets', 0) +
                cicids_row.get('Total Length of Bwd Packets', 0)
            ),
            packets_per_second=float(cicids_row.get('Flow Packets/s', 0)),
            bytes_per_second=float(cicids_row.get('Flow Bytes/s', 0)),
            flags=flags,
            threat_level=threat_level,
            threat_type=label if is_attack else None,
            is_attack=is_attack,
            metadata={
                'avg_packet_size': cicids_row.get('Average Packet Size', 0),
                'flow_iat_mean': cicids_row.get('Flow IAT Mean', 0),
                'fwd_psh_flags': cicids_row.get('Fwd PSH Flags', 0),
                'bwd_psh_flags': cicids_row.get('Bwd PSH Flags', 0)
            }
        )


class ThreatAlert(BaseModel):
    """Alert generated when threat is detected"""
    
    alert_id: str
    timestamp: datetime
    severity: ThreatLevel
    threat_type: str
    description: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    affected_logs: List[str] = Field(default_factory=list)
    mitre_technique_id: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert_001",
                "timestamp": "2024-11-13T10:30:00Z",
                "severity": "high",
                "threat_type": "SSH-Patator",
                "description": "Multiple failed SSH login attempts detected from distributed IPs",
                "confidence": 0.92,
                "affected_logs": ["log_001", "log_002", "log_003"],
                "mitre_technique_id": "T1110",
                "recommended_actions": [
                    "Rate-limit source IP",
                    "Enable account lockout policy",
                    "Review authentication logs"
                ]
            }
        }


if __name__ == "__main__":
    # Test schema
    print(" Testing Unified Schema...")
    
    log = SecurityLog(
        log_id="test_001",
        timestamp=datetime.now(),
        source=LogSource.CICIDS,
        source_ip="192.168.1.100",
        destination_port=22,
        action="ssh_attempt",
        status="failed",
        threat_level=ThreatLevel.HIGH,
        is_attack=True
    )
    
    print(" Schema validation passed!")
    print(f"\n Sample Log:")
    print(log.model_dump_json(indent=2))