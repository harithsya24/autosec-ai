"""
AutoSec AI - Main FastAPI Application
Autonomous Cloud Security & Threat Mitigation Agent
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import Body
import os
import sys
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
        
        return {
            "status": "analyzed",
            **result
        }
            
    except Exception as e:
        import traceback
        print(f"Analysis error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/v1/threats")
async def get_threats(limit: int = 10):
    """
    Get recent threat alerts
    """
    return {
        "threats": [],
        "total": 0,
        "limit": limit,
        "message": "Database connection pending - coming in Week 3"
    }

@app.get("/api/v1/threats/{alert_id}")
async def get_threat_detail(alert_id: str):
    """
    Get detailed information about a specific threat
    """
    raise HTTPException(
        status_code=404,
        detail=f"Threat {alert_id} not found - database not yet connected"
    )

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
        
        return {
            "status": "analyzed",
            **result
        }
        
    except Exception as e:
        import traceback
        print(f"Batch analysis error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

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