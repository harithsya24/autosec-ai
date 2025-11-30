"""
AutoSec AI - Main FastAPI Application
Autonomous Cloud Security & Threat Mitigation Agent
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from fastapi import Body
import os
import sys
import json
import asyncio
from pathlib import Path
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Import AI Agents
from agents.log_analyzer import LogAnalyzerAgent
from agents.orchestrator import OrchestratorAgent

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="AutoSec AI",
    description="Autonomous Cloud Security & Threat Mitigation Agent",
    version="0.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Global Agent Instances
# ============================================================================
log_analyzer = LogAnalyzerAgent(contamination=0.10)
orchestrator = OrchestratorAgent(sandbox_mode=True)
agent_initialized = False

# ============================================================================
# WebSocket Manager
# ============================================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# ============================================================================
# Pydantic Models (Data Schemas)
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    version: str
    services: Dict[str, str]

class LogEvent(BaseModel):
    """Security log event model"""
    timestamp: datetime
    source_ip: str
    user_id: Optional[str] = None
    action: str
    resource: str
    status: str
    metadata: Optional[Dict] = {}

class ThreatAlert(BaseModel):
    """Threat alert model"""
    alert_id: str
    severity: str  # "low", "medium", "high", "critical"
    confidence: float  # 0.0 to 1.0
    threat_type: str
    description: str
    timestamp: datetime
    affected_resources: List[str]

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - API welcome message"""
    return {
        "message": "Welcome to AutoSec AI API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint
    Returns the status of all system components
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(),
        version="0.1.0",
        services={
            "api": "operational",
            "database": "pending",  
            "rag": "pending",       
            "agents": "operational" if agent_initialized else "not_trained"
        }
    )

@app.get("/api/v1/status")
async def get_system_status():
    """
    Get current system status and statistics
    """
    return {
        "status": "running",
        "agent_initialized": agent_initialized,
        "agent_trained": log_analyzer.is_trained,
        "uptime": "0 hours",
        "threats_detected_today": 0,
        "alerts_generated": 0,
        "last_scan": None
    }

@app.get("/api/v1/agent/status")
async def agent_status():
    """
    Get AI agent initialization status
    """
    return {
        "initialized": agent_initialized,
        "model_trained": log_analyzer.is_trained,
        "contamination": log_analyzer.model.contamination if log_analyzer.is_trained else None,
        "message": "Agent ready for analysis" if agent_initialized else "Agent not trained. Call POST /api/v1/train"
    }

@app.post("/api/v1/train")
async def train_agent(
    sample_size: int = 15000, 
    benign_only: bool = True,
    use_multiple_files: bool = True
):
    """
    Train the AI agent on CICIDS dataset
    
    Args:
        sample_size: Total number of logs to train on (default: 15000)
        benign_only: Train on benign traffic only (default: True)
        use_multiple_files: Use multiple CICIDS files for diverse training (default: True)
    """
    global agent_initialized, log_analyzer
    
    try:
        import pandas as pd
        
        data_dir = Path(__file__).parent.parent.parent / "data" / "raw" / "cicids"
        
        if not data_dir.exists():
            raise HTTPException(
                status_code=404,
                detail=f"CICIDS dataset not found at {data_dir}"
            )
        
        all_logs = []
        
        if use_multiple_files:
            # Load from multiple files for better baseline
            csv_files = [
                "Monday-WorkingHours-pcap_ISCX.csv",
                "Tuesday-WorkingHours-pcap_ISCX.csv",
                "Wednesday-workingHours-pcap_ISCX.csv"
            ]
            
            print(f"📂 Loading from {len(csv_files)} CICIDS files...")
            per_file_samples = sample_size // len(csv_files)
            
            for csv_file in csv_files:
                file_path = data_dir / csv_file
                if file_path.exists():
                    try:
                        df = pd.read_csv(file_path, nrows=per_file_samples)
                        logs = df.to_dict('records')
                        all_logs.extend(logs)
                        print(f"    Loaded {len(logs)} from {csv_file}")
                    except Exception as e:
                        print(f"     Skipped {csv_file}: {e}")
                else:
                    print(f"     File not found: {csv_file}")
                        
            if not all_logs:
                raise HTTPException(
                    status_code=404,
                    detail="Could not load any CICIDS files. Check file names and paths."
                )
        else:
            # Use single file (original behavior)
            file_path = data_dir / "Friday-WorkingHours-Morning-pcap_ISCX.csv"
            if not file_path.exists():
                raise HTTPException(
                    status_code=404,
                    detail=f"CICIDS file not found at {file_path}"
                )
            df = pd.read_csv(file_path, nrows=sample_size)
            all_logs = df.to_dict('records')
            print(f" Loaded {len(all_logs)} logs from single file")
        
        print(f" Training agent (benign_only={benign_only}, multi_file={use_multiple_files})...")
        print(f"   Total logs loaded: {len(all_logs)}")
        
        if benign_only:
            stats = log_analyzer.train_on_benign_only(all_logs)
        else:
            stats = log_analyzer.train(all_logs)
        
        agent_initialized = True
        
        # Update orchestrator with trained log analyzer
        orchestrator.log_analyzer = log_analyzer
        
        print(" Agent trained successfully!")
        
        return {
            "status": "success",
            "message": "Agent trained successfully",
            "stats": stats,
            "training_mode": "benign_only" if benign_only else "all_data",
            "files_used": len(csv_files) if use_multiple_files else 1,
            "training_data_size": len(all_logs)
        }
        
    except Exception as e:
        import traceback
        print(f" Training error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

@app.post("/api/v1/logs/ingest")
async def ingest_log(log: LogEvent):
    """
    Ingest a security log event
    This will be the entry point for log data
    """
    return {
        "status": "received",
        "log_id": f"log_{datetime.now().timestamp()}",
        "message": "Log ingested successfully",
        "log": log.model_dump()
    }

@app.post("/api/v1/analyze")
async def analyze_log(log: LogEvent, full_analysis: bool = True):
    """
    Analyze a log event for threats using full AI agent pipeline
    
    Args:
        log: Log event to analyze
        full_analysis: If True, includes RAG + LLM analysis (default: True)
    
    Returns:
        Complete analysis with detection, explanation, and recommendations
    """
    global agent_initialized, orchestrator
    
    # Check if agent is trained
    if not agent_initialized:
        raise HTTPException(
            status_code=400,
            detail="Agent not initialized. Please call POST /api/v1/train first"
        )
    
    try:
        # Convert LogEvent to dict format expected by agent
        raw_log = {
            'timestamp': log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else log.timestamp,
            'source_ip': log.source_ip,
            'destination_ip': '0.0.0.0',
            'user_id': log.user_id or 'unknown',
            'action': log.action,
            'resource': log.resource,
            'status': log.status,
            'protocol': 'TCP',
            'port': 443,
            'bytes_sent': log.metadata.get('bytes_sent', 0),
            'bytes_received': log.metadata.get('bytes_received', 0),
            'duration': log.metadata.get('duration', 0.0),
            'metadata': log.metadata or {}
        }
        
        # Use orchestrator for complete analysis
        result = orchestrator.analyze_log(raw_log, return_full_analysis=full_analysis)
        
        # Save threat to database if detected
        if result.get('threat_detected'):
            try:
                from backend.utils.database import SecurityLogDatabase
                
                db = SecurityLogDatabase()
                alert_id = f"threat_{datetime.now().timestamp()}"
                
                # Format threat data for storage
                threat_data = {
                    "alert_id": alert_id,
                    "timestamp": result.get('anomaly', {}).get('timestamp', datetime.now()),
                    "severity": result.get('threat_analysis', {}).get('severity', result.get('anomaly', {}).get('severity', 'medium')),
                    "confidence": result.get('threat_analysis', {}).get('confidence', 0.5),
                    "threat_type": result.get('threat_analysis', {}).get('threat_type', 'Unknown'),
                    "description": result.get('threat_analysis', {}).get('explanation', 'Threat detected'),
                    "anomaly": result.get('anomaly', {}),
                    "status": "detected",
                    "threat_analysis": result.get('threat_analysis', {}),
                    "recommended_actions": result.get('recommended_actions', {}).get('actions', {}),
                    "executed_actions": result.get('executed_actions', []),
                    "pending_actions": result.get('pending_actions', []),
                    "matched_techniques": result.get('threat_analysis', {}).get('matched_techniques', []),
                    "affected_resources": [result.get('anomaly', {}).get('resource', '')] if result.get('anomaly', {}).get('resource') else []
                }
                
                db.insert_threat(threat_data)
                
                # Update result with alert_id
                result['alert_id'] = alert_id
            except Exception as e:
                print(f"Warning: Failed to save threat to database: {e}")
            
            # Broadcast threat detection via WebSocket
            await manager.broadcast({
                "type": "threat_detected",
                "data": {
                    **result,
                    "alert_id": result.get('alert_id', f"threat_{datetime.now().timestamp()}")
                },
                "timestamp": datetime.now().isoformat()
            })
        
        # Broadcast action execution
        if result.get('executed_actions'):
            for action in result.get('executed_actions', []):
                await manager.broadcast({
                    "type": "action_executed",
                    "data": action,
                    "timestamp": datetime.now().isoformat()
                })
        
        return {
            "status": "analyzed",
            **result
        }
            
    except Exception as e:
        import traceback
        print(f"Analysis error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/v1/threats")
async def get_threats(limit: int = 50, severity: Optional[str] = None):
    """
    Get recent threat alerts from database
    """
    try:
        from backend.utils.database import SecurityLogDatabase
        
        db = SecurityLogDatabase()
        threats = db.get_threats(limit=limit, severity=severity)
        
        # Convert to frontend format
        formatted_threats = []
        for threat in threats:
            formatted_threat = {
                "alert_id": threat.get("alert_id"),
                "severity": threat.get("severity", "medium"),
                "confidence": threat.get("confidence", 0.5),
                "threat_type": threat.get("threat_type", "Unknown"),
                "description": threat.get("description", ""),
                "timestamp": threat.get("timestamp").isoformat() if isinstance(threat.get("timestamp"), datetime) else threat.get("timestamp"),
                "affected_resources": threat.get("affected_resources", []),
                "anomaly_score": threat.get("anomaly_score"),
                "matched_techniques": threat.get("matched_techniques", []),
                "recommended_actions": threat.get("recommended_actions", []),
                "executed_actions": threat.get("executed_actions", []),
                "pending_actions": threat.get("pending_actions", []),
                "threat_analysis": threat.get("threat_analysis", {})
            }
            formatted_threats.append(formatted_threat)
        
        return {
            "status": "success",
            "threats": formatted_threats,
            "total": len(formatted_threats),
            "limit": limit
        }
    except Exception as e:
        import traceback
        print(f"Error getting threats:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to get threats: {str(e)}")

@app.get("/api/v1/threats/{alert_id}")
async def get_threat_detail(alert_id: str):
    """
    Get detailed information about a specific threat
    """
    try:
        from backend.utils.database import SecurityLogDatabase
        
        db = SecurityLogDatabase()
        threat = db.get_threat_by_id(alert_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {alert_id} not found")
        
        # Convert to frontend format
        formatted_threat = {
            "alert_id": threat.get("alert_id"),
            "severity": threat.get("severity", "medium"),
            "confidence": threat.get("confidence", 0.5),
            "threat_type": threat.get("threat_type", "Unknown"),
            "description": threat.get("description", ""),
            "timestamp": threat.get("timestamp").isoformat() if isinstance(threat.get("timestamp"), datetime) else threat.get("timestamp"),
            "affected_resources": threat.get("affected_resources", []),
            "anomaly_score": threat.get("anomaly_score"),
            "matched_techniques": threat.get("matched_techniques", []),
            "recommended_actions": threat.get("recommended_actions", []),
            "executed_actions": threat.get("executed_actions", []),
            "pending_actions": threat.get("pending_actions", []),
            "threat_analysis": threat.get("threat_analysis", {})
        }
        
        return {
            "status": "success",
            **formatted_threat
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Error getting threat detail:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to get threat: {str(e)}")

@app.get("/api/v1/system/status")
async def get_system_status():
    """
    Get comprehensive system status including all agents
    """
    global orchestrator
    
    status = orchestrator.get_system_status()
    
    return {
        "status": "operational",
        "agents": status,
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# Action Management Endpoints (Week 3)
# ============================================================================

@app.get("/api/v1/actions/pending")
async def get_pending_actions():
    """
    Get all pending actions requiring approval
    """
    global orchestrator
    
    try:
        pending = orchestrator.action_executor.get_pending_actions()
        return {
            "status": "success",
            "count": len(pending),
            "actions": pending,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get pending actions: {str(e)}")

@app.post("/api/v1/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    approver: str = Body(...),
    reason: Optional[str] = Body(None)
):
    """
    Approve a pending action
    
    Args:
        action_id: ID of the action to approve
        approver: Username/ID of the person approving
        reason: Optional reason for approval
    """
    global orchestrator
    
    try:
        result = orchestrator.action_executor.approve_action(action_id, approver, reason)
        
        # Broadcast action approval via WebSocket
        await manager.broadcast({
            "type": "action_approved",
            "data": result,
            "timestamp": datetime.now().isoformat()
        })
        
        return {
            "status": "success",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to approve action: {str(e)}")

@app.post("/api/v1/actions/{action_id}/reject")
async def reject_action(
    action_id: str,
    approver: str = Body(...),
    reason: Optional[str] = Body(None)
):
    """
    Reject a pending action
    
    Args:
        action_id: ID of the action to reject
        approver: Username/ID of the person rejecting
        reason: Optional reason for rejection
    """
    global orchestrator
    
    try:
        result = orchestrator.action_executor.reject_action(action_id, approver, reason)
        return {
            "status": "success",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reject action: {str(e)}")

@app.get("/api/v1/actions/history")
async def get_action_history(limit: int = 50):
    """
    Get action execution history
    
    Args:
        limit: Maximum number of actions to return
    """
    global orchestrator
    
    try:
        history = orchestrator.action_executor.get_action_history(limit)
        return {
            "status": "success",
            "count": len(history),
            "actions": history,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get action history: {str(e)}")

@app.post("/api/v1/actions/{action_id}/rollback")
async def rollback_action(
    action_id: str,
    reason: Optional[str] = Body(None)
):
    """
    Rollback a completed action
    
    Args:
        action_id: ID of the action to rollback
        reason: Optional reason for rollback
    """
    global orchestrator
    
    try:
        result = orchestrator.action_executor.rollback_action(action_id, reason)
        return {
            "status": "success",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rollback action: {str(e)}")

@app.get("/api/v1/actions/{action_id}")
async def get_action_detail(action_id: str):
    """
    Get details of a specific action
    """
    global orchestrator
    
    try:
        import sqlite3
        from backend.utils.database import SecurityLogDatabase
        
        db = SecurityLogDatabase()
        conn = sqlite3.connect(
            db.db_path, 
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10.0
        )
        try:
            conn.row_factory = lambda cursor, row: {
                col[0]: row[idx] for idx, col in enumerate(cursor.description)
            }
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
            action = cursor.fetchone()
            
            if not action:
                raise HTTPException(status_code=404, detail="Action not found")
            
            # Get approval history if exists
            cursor.execute('''
                SELECT * FROM action_approvals
                WHERE action_id = ?
                ORDER BY approved_at DESC
            ''', (action_id,))
            approvals = cursor.fetchall()
            
            # Parse JSON fields
            if action.get('parameters'):
                action['parameters'] = json.loads(action['parameters'])
            if action.get('rollback_info'):
                action['rollback_info'] = json.loads(action['rollback_info'])
            
            return {
                "status": "success",
                "action": action,
                "approvals": approvals
            }
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get action: {str(e)}")

@app.post("/api/v1/analyze/batch")
async def analyze_batch_logs(
    logs: List[LogEvent],
    full_analysis: bool = False
):
    """
    Analyze multiple logs in batch
    
    Args:
        logs: List of log events to analyze
        full_analysis: If True, includes RAG + LLM for each (default: False for performance)
    
    Returns:
        Batch analysis results
    """
    global agent_initialized, orchestrator
    
    if not agent_initialized:
        raise HTTPException(
            status_code=400,
            detail="Agent not initialized. Please call POST /api/v1/train first"
        )
    
    try:
        # Convert LogEvents to dict format
        raw_logs = []
        for log in logs:
            raw_log = {
                'timestamp': log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else log.timestamp,
                'source_ip': log.source_ip,
                'destination_ip': '0.0.0.0',
                'user_id': log.user_id or 'unknown',
                'action': log.action,
                'resource': log.resource,
                'status': log.status,
                'protocol': 'TCP',
                'port': 443,
                'bytes_sent': log.metadata.get('bytes_sent', 0),
                'bytes_received': log.metadata.get('bytes_received', 0),
                'duration': log.metadata.get('duration', 0.0),
                'metadata': log.metadata or {}
            }
            raw_logs.append(raw_log)
        
        # Use orchestrator for batch analysis
        result = orchestrator.analyze_batch(raw_logs, return_full_analysis=full_analysis)
        
        # Broadcast threat detections via WebSocket
        if result.get('threat_detected'):
            await manager.broadcast({
                "type": "threat_detected",
                "data": result,
                "timestamp": datetime.now().isoformat()
            })
        
        return {
            "status": "analyzed",
            **result
        }
        
    except Exception as e:
        import traceback
        print(f"Batch analysis error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Echo back or handle client messages
            await manager.send_personal_message({
                "type": "message",
                "data": {"echo": data},
                "timestamp": datetime.now().isoformat()
            }, websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ============================================================================
# Compliance Reporting Endpoints (Week 4)
# ============================================================================

class ComplianceReportRequest(BaseModel):
    type: str  # "soc2", "gdpr", "hipaa", "custom"
    period_start: str
    period_end: str

@app.post("/api/v1/compliance/reports")
async def generate_compliance_report(request: ComplianceReportRequest):
    """
    Generate a compliance report using LLM-powered analysis
    
    Args:
        request: Report type and date range
    
    Returns:
        Generated compliance report
    """
    global orchestrator
    
    try:
        from agents.compliance_agent import ComplianceAgent
        
        compliance_agent = ComplianceAgent()
        report = await compliance_agent.generate_report(
            report_type=request.type,
            start_date=request.period_start,
            end_date=request.period_end
        )
        
        return report
        
    except Exception as e:
        import traceback
        print(f"Compliance report error:\n{traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate compliance report: {str(e)}"
        )

@app.get("/api/v1/compliance/reports")
async def get_compliance_reports():
    """
    Get list of generated compliance reports
    """
    # TODO: Store reports in database
    return {
        "status": "success",
        "reports": [],
        "message": "Report storage coming soon"
    }

@app.get("/api/v1/compliance/reports/{report_id}")
async def get_compliance_report(report_id: str):
    """
    Get a specific compliance report by ID
    """
    raise HTTPException(
        status_code=404,
        detail="Report storage not yet implemented"
    )

# ============================================================================
# Startup and Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """
    Run initialization tasks when the server starts
    """
    print(" AutoSec AI starting up...")
    print(f" API Documentation: http://localhost:8000/docs")
    print(f" Health Check: http://localhost:8000/health")
    print(f" Agent Status: http://localhost:8000/api/v1/agent/status")
    print(f"\n To train the agent: POST http://localhost:8000/api/v1/train")

@app.on_event("shutdown")
async def shutdown_event():
    """
    Clean up resources when the server shuts down
    """
    print(" AutoSec AI shutting down...")

# ============================================================================
# Run the server (for development)
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Get configuration from environment variables
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    reload = os.getenv("API_RELOAD", "true").lower() == "true"
    
    print(f"  Starting AutoSec AI on {host}:{port}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )