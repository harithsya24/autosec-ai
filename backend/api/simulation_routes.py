"""
Simulation API Routes
Endpoints for controlling threat simulation
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from backend.simulation.threat_simulator import ThreatSimulator, ThreatType, ActionTier
from backend.utils.database import SecurityLogDatabase

router = APIRouter(prefix="/api/v1/simulation", tags=["simulation"])

# Global simulator instance (will be initialized in main.py)
simulator: Optional[ThreatSimulator] = None
websocket_manager = None  # Will be set from main.py


# Request/Response Models
class SimulationConfig(BaseModel):
    interval_seconds: Optional[int] = 45
    enabled_threats: Optional[List[str]] = None
    auto_clear_low_priority: Optional[bool] = False
    clear_after_seconds: Optional[int] = 120


class DemoConfig(BaseModel):
    duration_minutes: int = 5


class ThreatResponse(BaseModel):
    threat_detected: bool
    status: str
    anomaly: Optional[Dict[str, Any]] = None
    threat_analysis: Optional[Dict[str, Any]] = None
    recommended_actions: Optional[Dict[str, Any]] = None
    executed_actions: Optional[List[Dict[str, Any]]] = None
    pending_actions: Optional[List[Dict[str, Any]]] = None
    simulation_metadata: Optional[Dict[str, Any]] = None


async def broadcast_threat(websocket_manager, threat_data: Dict):
    """Broadcast threat to all connected WebSocket clients"""
    if websocket_manager:
        await websocket_manager.broadcast({
            "type": "threat_detected",
            "data": threat_data,
            "timestamp": datetime.now().isoformat()
        })


async def save_threat_to_database(threat_data: Dict):
    """Save threat to database"""
    try:
        db = SecurityLogDatabase()
        
        # Extract alert_id from threat data
        alert_id = threat_data.get("alert_id") or f"sim_{datetime.now().timestamp()}"
        
        # Prepare threat data for database
        anomaly = threat_data.get("anomaly", {})
        threat_analysis = threat_data.get("threat_analysis", {})
        recommended_actions = threat_data.get("recommended_actions", {})
        executed_actions = threat_data.get("executed_actions", [])
        pending_actions = threat_data.get("pending_actions", [])
        
        # Get MITRE techniques
        matched_techniques = threat_analysis.get("matched_techniques", [])
        if isinstance(matched_techniques, list):
            matched_techniques_str = ",".join(matched_techniques)
        else:
            matched_techniques_str = str(matched_techniques) if matched_techniques else ""
        
        # Insert threat
        db.insert_threat(
            alert_id=alert_id,
            timestamp=anomaly.get("timestamp", datetime.now()),
            severity=anomaly.get("severity", "medium"),
            confidence=threat_analysis.get("confidence", 0.0),
            threat_type=threat_analysis.get("threat_type", "unknown"),
            description=threat_analysis.get("explanation", ""),
            anomaly_score=anomaly.get("anomaly_score", 0.0),
            source_ip=anomaly.get("source_ip", ""),
            user_id=anomaly.get("user_id", ""),
            resource=anomaly.get("resource", ""),
            status=anomaly.get("status", ""),
            threat_analysis=threat_analysis,
            recommended_actions=recommended_actions,
            executed_actions=executed_actions,
            pending_actions=pending_actions,
            matched_techniques=matched_techniques_str
        )
    except Exception as e:
        print(f"Error saving threat to database: {e}")


@router.post("/start")
async def start_simulation():
    """Start continuous threat simulation"""
    global simulator
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    if simulator.is_running:
        return {"status": "already_running", "message": "Simulation is already running"}
    
    await simulator.start_continuous_simulation()
    
    return {
        "status": "started",
        "message": "Threat simulation started",
        "config": simulator.config
    }


@router.post("/start-demo")
async def start_demo_mode(config: DemoConfig):
    """Start demo mode with pre-planned threats"""
    global simulator
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    if simulator.is_running:
        return {"status": "already_running", "message": "Simulation is already running"}
    
    print(f"Starting demo mode for {config.duration_minutes} minutes...")
    await simulator.start_demo_mode(duration_minutes=config.duration_minutes)
    print(f"Demo mode started - {len(simulator.demo_threats_plan)} threats planned")
    
    return {
        "status": "demo_started",
        "message": f"Demo mode started for {config.duration_minutes} minutes",
        "duration_minutes": config.duration_minutes,
        "planned_threats": len(simulator.demo_threats_plan)
    }


@router.post("/stop")
async def stop_simulation():
    """Stop threat simulation"""
    global simulator
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    if not simulator.is_running:
        return {"status": "not_running", "message": "Simulation is not running"}
    
    await simulator.stop_simulation()
    
    return {
        "status": "stopped",
        "message": "Threat simulation stopped",
        "threats_generated": len(simulator.generated_threats)
    }


@router.get("/status")
async def get_simulation_status():
    """Get simulation status"""
    global simulator
    
    if not simulator:
        return {
            "status": "not_initialized",
            "is_running": False,
            "message": "Simulator not initialized"
        }
    
    status = simulator.get_status()
    return {
        "status": "ok",
        **status
    }


@router.post("/config")
async def update_simulation_config(config: SimulationConfig):
    """Update simulation configuration"""
    global simulator
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    update_dict = {}
    if config.interval_seconds is not None:
        update_dict["interval_seconds"] = config.interval_seconds
    if config.enabled_threats is not None:
        # Convert string threat types to ThreatType enum
        threat_types = []
        for threat_str in config.enabled_threats:
            try:
                threat_types.append(ThreatType[threat_str.upper()])
            except KeyError:
                # Try value match
                for tt in ThreatType:
                    if tt.value == threat_str.lower():
                        threat_types.append(tt)
                        break
        update_dict["enabled_threats"] = threat_types if threat_types else list(ThreatType)
    if config.auto_clear_low_priority is not None:
        update_dict["auto_clear_low_priority"] = config.auto_clear_low_priority
    if config.clear_after_seconds is not None:
        update_dict["clear_after_seconds"] = config.clear_after_seconds
    
    simulator.update_config(**update_dict)
    
    return {
        "status": "updated",
        "message": "Simulation configuration updated",
        "config": simulator.config
    }


@router.post("/next-threat")
async def generate_next_threat():
    """Generate next threat immediately"""
    global simulator, websocket_manager
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    try:
        threat_result = await simulator.generate_next_threat()
        
        # Save to database
        await save_threat_to_database(threat_result)
        
        # Broadcast via WebSocket
        await broadcast_threat(websocket_manager, threat_result)
        
        return {
            "status": "success",
            "threat": threat_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate threat: {str(e)}")


@router.get("/threats")
async def get_generated_threats():
    """Get all generated threats"""
    global simulator
    
    if not simulator:
        return {"threats": [], "count": 0}
    
    return {
        "threats": simulator.generated_threats[-50:],  # Last 50 threats
        "count": len(simulator.generated_threats),
        "total": len(simulator.generated_threats)
    }


@router.post("/clear")
async def clear_threats():
    """Clear generated threats history"""
    global simulator
    
    if not simulator:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    
    count = len(simulator.generated_threats)
    simulator.generated_threats.clear()
    
    return {
        "status": "cleared",
        "message": f"Cleared {count} threats from history"
    }

