# AutoSec AI - Agent System Setup Guide

##  Overview

AutoSec AI now includes a complete multi-agent system for threat detection, analysis, and response:

1. **Log Analyzer Agent** - Detects anomalies using Isolation Forest
2. **Threat Intelligence Agent** - Explains threats using RAG + LLM
3. **Response Agent** - Recommends actions with traffic light system
4. **Orchestrator Agent** - Coordinates the entire workflow

##  Quick Start

### 1. Environment Setup

Create a `.env` file in the project root:

```bash

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true

# Sandbox Mode (safe for testing)
SANDBOX_MODE=true
```

**Note:** The system works without OpenAI API key, but will use template-based explanations instead of LLM reasoning.

### 2. Initialize RAG System

First, populate the threat intelligence vector store:

```python
from rag.vector_store.chroma_setup import (
    ThreatIntelligenceRAG,
    create_sample_threat_documents,
    create_sample_cve_documents,
    create_sample_incident_reports
)

# Initialize RAG
rag = ThreatIntelligenceRAG()

# Load sample data
rag.add_threat_documents(create_sample_threat_documents())
rag.add_cve_documents(create_sample_cve_documents())
rag.add_incident_reports(create_sample_incident_reports())

print(f"RAG initialized: {rag.get_collection_stats()}")
```

### 3. Train the Log Analyzer

```bash
# Via API
curl -X POST "http://localhost:8000/api/v1/train?sample_size=15000&benign_only=true"

# Or via Python
from backend.agents.log_analyzer import LogAnalyzerAgent
from backend.utils.data_loader import CICIDSLoader

loader = CICIDSLoader()
df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=15000)
logs = df.to_dict('records')

agent = LogAnalyzerAgent()
agent.train_on_benign_only(logs)
```

### 4. Start the API Server

```bash
cd backend/api
python main.py
```

Or using uvicorn:

```bash
uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000
```

##  API Endpoints

### Analyze Single Log

```bash
POST /api/v1/analyze
Content-Type: application/json

{
  "timestamp": "2024-11-13T10:30:00Z",
  "source_ip": "203.45.67.89",
  "user_id": "user_123",
  "action": "login",
  "resource": "/api/auth",
  "status": "failed",
  "metadata": {
    "bytes_sent": 0,
    "bytes_received": 0,
    "duration": 0.5
  }
}
```

**Response includes:**
- Threat detection result
- RAG-powered explanation
- Confidence score
- Matched MITRE ATT&CK techniques
- Recommended actions (G/Y/R tiers)

### Analyze Batch

```bash
POST /api/v1/analyze/batch?full_analysis=false
Content-Type: application/json

[
  { /* log 1 */ },
  { /* log 2 */ },
  ...
]
```

### System Status

```bash
GET /api/v1/system/status
```

Returns status of all agents (trained, LLM enabled, etc.)

##  Agent Details

### Log Analyzer Agent

**Purpose:** Detect anomalies in security logs

**Model:** Isolation Forest (unsupervised learning)

**Input:** Raw log dictionary

**Output:** Anomaly score, severity level

**Usage:**
```python
from backend.agents.log_analyzer import LogAnalyzerAgent

agent = LogAnalyzerAgent(contamination=0.10)
agent.train_on_benign_only(training_logs)
anomalies, results_df = agent.detect_anomalies([log])
```

### Threat Intelligence Agent

**Purpose:** Explain detected threats using RAG + LLM

**Components:**
- RAG: ChromaDB vector store with MITRE ATT&CK, CVE, incidents
- LLM: GPT-4o-mini (optional, falls back to templates)

**Input:** Detected anomaly

**Output:** 
- Threat type classification
- Human-readable explanation
- Confidence score
- Matched techniques
- Recommendations

**Usage:**
```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()
agent = ThreatIntelligenceAgent(rag=rag, use_llm=True)
analysis = agent.analyze_threat(anomaly)
```

### Response Agent

**Purpose:** Recommend mitigation actions with risk tiers

**Traffic Light System:**
-  **GREEN**: Auto-execute (log, alert, monitor)
-  **YELLOW**: Auto-execute + notify (rate-limit, flag)
-  **RED**: Require approval (lock account, block IP)

**Usage:**
```python
from backend.agents.response_agent import ResponseAgent

agent = ResponseAgent(sandbox_mode=True)
recommendations = agent.recommend_actions(threat_analysis, anomaly)
```

### Orchestrator Agent

**Purpose:** Coordinate the entire workflow

**Workflow:**
1. Log Analyzer → Detect anomalies
2. Threat Intelligence → Explain threats
3. Response Agent → Recommend actions
4. Return complete analysis

**Usage:**
```python
from backend.agents.orchestrator import OrchestratorAgent

orchestrator = OrchestratorAgent(sandbox_mode=True)
result = orchestrator.analyze_log(raw_log, return_full_analysis=True)
```

##  Configuration

### LLM Settings

In `threat_intelligence_agent.py`:

```python
agent = ThreatIntelligenceAgent(
    rag=rag,
    llm_model="gpt-4o-mini",  # or "gpt-4", "gpt-3.5-turbo"
    temperature=0.3,  # Lower = more deterministic
    use_llm=True  # Set False to disable LLM (RAG only)
)
```

### Sandbox Mode

All actions are logged but not executed in sandbox mode:

```python
response_agent = ResponseAgent(sandbox_mode=True)
```

Set to `False` for production ( **use with caution**)

##  Example Workflow

```python
from backend.agents.orchestrator import OrchestratorAgent

# Initialize
orchestrator = OrchestratorAgent(sandbox_mode=True)

# Train (one-time)
# ... training code ...

# Analyze a log
raw_log = {
    "action": "login",
    "status": "failed",
    "source_ip": "203.45.67.89",
    # ... other fields
}

result = orchestrator.analyze_log(raw_log, return_full_analysis=True)

if result["threat_detected"]:
    print(f"Threat: {result['threat_analysis']['threat_type']}")
    print(f"Confidence: {result['threat_analysis']['confidence']:.2%}")
    print(f"Explanation: {result['threat_analysis']['explanation']}")
    
    actions = result["recommended_actions"]["actions"]
    print(f"\n Green actions: {len(actions['green'])}")
    print(f" Yellow actions: {len(actions['yellow'])}")
    print(f" Red actions: {len(actions['red'])}")
```

##  Testing

### Test Individual Agents

```bash
# Test Log Analyzer
python backend/agents/log_analyzer.py

# Test Threat Intelligence Agent
python backend/agents/threat_intelligence_agent.py

# Test Response Agent
python backend/agents/response_agent.py

# Test Orchestrator
python backend/agents/orchestrator.py
```

### Test via API

```bash
# Health check
curl http://localhost:8000/health

# System status
curl http://localhost:8000/api/v1/system/status

# Analyze log
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-11-13T10:30:00Z",
    "source_ip": "203.45.67.89",
    "action": "login",
    "resource": "/api/auth",
    "status": "failed",
    "metadata": {}
  }'
```

##  Troubleshooting

### LLM Not Working

1. Check `OPENAI_API_KEY` is set in `.env`
2. Verify API key is valid
3. Check internet connection
4. System will fall back to template-based explanations

### RAG Returns No Results

1. Ensure threat intelligence is loaded:
   ```python
   rag = ThreatIntelligenceRAG()
   print(rag.get_collection_stats())  # Should show > 0
   ```

2. Load sample data if empty:
   ```python
   from rag.vector_store.chroma_setup import create_sample_threat_documents
   rag.add_threat_documents(create_sample_threat_documents())
   ```

### Agent Not Trained

```bash
# Train via API
POST /api/v1/train?sample_size=15000&benign_only=true
```

##  Next Steps

1. **Week 3**: Add autonomous mitigation execution
2. **Week 4**: Build React dashboard
3. **Production**: Disable sandbox mode and add monitoring

##  Related Documentation

- [Architecture Overview](./architecture.md)
- [Week 1 Progress](./week1_progress.md)
- [API Documentation](http://localhost:8000/docs)

