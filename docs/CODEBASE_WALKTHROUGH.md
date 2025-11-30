# AutoSec AI - Complete Codebase Walkthrough

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Flow](#architecture-flow)
3. [Component-by-Component Breakdown](#component-by-component-breakdown)
4. [Data Flow](#data-flow)
5. [Manual Testing Guide](#manual-testing-guide)
6. [Key Files Reference](#key-files-reference)

---

## 🎯 System Overview

**AutoSec AI** is an autonomous security system that:
1. **Detects** threats in network logs using ML
2. **Explains** threats using AI (RAG + LLM)
3. **Recommends** mitigation actions
4. **Executes** safe actions automatically
5. **Displays** everything in a real-time dashboard

---

## 🏗️ Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    USER / SECURITY ANALYST                   │
│              (Dashboard at http://localhost:3000)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ HTTP Requests / WebSocket
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    FASTAPI BACKEND                            │
│              (backend/api/main.py)                           │
│  - REST API Endpoints                                        │
│  - WebSocket Server                                          │
│  - Request Routing                                           │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Orchestrator│  │  Database   │  │  WebSocket  │
│   Agent     │  │  (SQLite)   │  │  Manager    │
└──────┬──────┘  └─────────────┘  └─────────────┘
       │
       │ Coordinates workflow
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    AI AGENT PIPELINE                         │
│                                                               │
│  Step 1: Log Analyzer Agent                                  │
│  ├─ Input: Raw log data                                      │
│  ├─ Process: Isolation Forest anomaly detection             │
│  └─ Output: Anomaly score + severity                         │
│                                                               │
│  Step 2: Threat Intelligence Agent                          │
│  ├─ Input: Detected anomaly                                  │
│  ├─ Process: RAG retrieval + LLM reasoning                  │
│  └─ Output: Threat explanation + confidence                │
│                                                               │
│  Step 3: Response Agent                                      │
│  ├─ Input: Threat analysis                                   │
│  ├─ Process: Traffic light classification                   │
│  └─ Output: Action recommendations (Green/Yellow/Red)     │
│                                                               │
│  Step 4: Action Executor                                     │
│  ├─ Input: Recommended actions                               │
│  ├─ Process: Execute green/yellow, queue red                │
│  └─ Output: Execution results                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Component-by-Component Breakdown

### 1. **Entry Point: FastAPI Backend**

**File:** `backend/api/main.py`

**Purpose:** Main API server that handles all HTTP requests and WebSocket connections

**Key Functions:**

```python
# Health check
GET /health
→ Returns system status

# Train the ML model
POST /api/v1/train
→ Trains Isolation Forest on benign traffic
→ Required before analysis

# Analyze a log
POST /api/v1/analyze
→ Main entry point for threat detection
→ Flow: Log → Orchestrator → All Agents → Response

# Get threats
GET /api/v1/threats
→ Returns all detected threats from database

# Action management
GET /api/v1/actions/pending
POST /api/v1/actions/{id}/approve
POST /api/v1/actions/{id}/reject
POST /api/v1/actions/{id}/rollback

# WebSocket
WS /ws
→ Real-time updates for dashboard
```

**How It Works:**
1. Receives log via `POST /api/v1/analyze`
2. Calls `orchestrator.analyze_log()`
3. Saves threat to database if detected
4. Broadcasts via WebSocket
5. Returns complete analysis

**Manual Check:**
```bash
# Start server
cd backend/api
python main.py

# Test health
curl http://localhost:8000/health

# Check API docs
open http://localhost:8000/docs
```

---

### 2. **Orchestrator Agent**

**File:** `backend/agents/orchestrator.py`

**Purpose:** Coordinates the entire workflow between all agents

**Key Methods:**

```python
analyze_log(raw_log, return_full_analysis=True)
→ Step 1: Log Analyzer detects anomalies
→ Step 2: Threat Intelligence explains threat (RAG + LLM)
→ Step 3: Response Agent recommends actions
→ Step 4: Action Executor executes safe actions
→ Returns: Complete analysis with all results
```

**Flow:**
```
Raw Log
  ↓
[Log Analyzer] → Anomaly detected? Yes/No
  ↓ (if yes)
[Threat Intelligence] → RAG retrieval → LLM analysis
  ↓
[Response Agent] → Classify actions (Green/Yellow/Red)
  ↓
[Action Executor] → Execute green/yellow, queue red
  ↓
Complete Result
```

**Manual Check:**
```python
from backend.agents.orchestrator import OrchestratorAgent

orchestrator = OrchestratorAgent(sandbox_mode=True)
# Train first (see Log Analyzer section)
result = orchestrator.analyze_log(test_log)
print(result)
```

---

### 3. **Log Analyzer Agent**

**File:** `backend/agents/log_analyzer.py`

**Purpose:** Detects anomalies in network logs using Isolation Forest

**Key Components:**

```python
class LogAnalyzerAgent:
    - model: IsolationForest (scikit-learn)
    - scaler: StandardScaler (normalizes features)
    - preprocessor: LogPreprocessor (extracts features)
```

**Training Process:**
```python
train_on_benign_only(logs)
→ Loads benign traffic
→ Extracts ML features (flow duration, packets, bytes, etc.)
→ Trains Isolation Forest model
→ Model learns "normal" patterns
→ Saves model to disk
```

**Detection Process:**
```python
detect_anomalies(logs)
→ Extract features from logs
→ Scale features
→ Run through Isolation Forest
→ Get anomaly scores (-1 = anomaly, +1 = normal)
→ Classify severity (low/medium/high/critical)
→ Return anomalies with scores
```

**Key Features Extracted:**
- Flow Duration
- Total Packets (forward + backward)
- Flow Bytes/s
- Flow Packets/s
- Destination Port
- Packet length statistics
- Flag counts (SYN, ACK, FIN, etc.)

**Manual Check:**
```python
from backend.agents.log_analyzer import LogAnalyzerAgent

agent = LogAnalyzerAgent(contamination=0.10)

# Train on benign data
benign_logs = [...]  # Load from CICIDS Monday file
agent.train_on_benign_only(benign_logs)
print(f"Trained: {agent.is_trained}")

# Detect anomalies
test_log = {...}  # Suspicious log
anomalies, df = agent.detect_anomalies([test_log])
print(f"Anomalies: {len(anomalies)}")
print(f"Score: {anomalies[0]['anomaly_score']}")
```

---

### 4. **Threat Intelligence Agent**

**File:** `backend/agents/threat_intelligence_agent.py`

**Purpose:** Explains detected threats using RAG (Retrieval-Augmented Generation) + LLM

**Key Components:**

```python
class ThreatIntelligenceAgent:
    - rag: ThreatIntelligenceRAG (vector store)
    - llm: ChatOpenAI (LangChain wrapper)
```

**Analysis Process:**
```python
analyze_threat(anomaly)
→ Step 1: Create query from anomaly
→ Step 2: RAG retrieval (search vector store)
   - Searches MITRE ATT&CK techniques
   - Searches CVE database
   - Searches historical incidents
→ Step 3: LLM reasoning (if available)
   - Uses retrieved context
   - Generates explanation
   - Calculates confidence
→ Step 4: Extract matched techniques
→ Returns: Threat type, explanation, confidence, citations
```

**RAG Retrieval:**
- Query: "multiple failed logins from distributed IPs"
- Retrieves: Top 3 similar threat patterns
- Returns: MITRE techniques, CVE descriptions, past incidents

**LLM Reasoning:**
- Input: Anomaly + Retrieved context
- Prompt: "Explain this threat based on the context..."
- Output: Human-readable explanation with citations

**Manual Check:**
```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()
agent = ThreatIntelligenceAgent(rag=rag, use_llm=True)

anomaly = {
    "action": "login",
    "status": "failed",
    "anomaly_score": -0.85,
    "severity": "high"
}

analysis = agent.analyze_threat(anomaly)
print(f"Threat Type: {analysis['threat_type']}")
print(f"Confidence: {analysis['confidence']}")
print(f"Explanation: {analysis['explanation']}")
print(f"Matched Techniques: {analysis['matched_techniques']}")
```

---

### 5. **Response Agent**

**File:** `backend/agents/response_agent.py`

**Purpose:** Recommends mitigation actions using "Traffic Light" system

**Traffic Light System:**

```python
GREEN (Auto-Execute):
- log_event: Log to database
- send_alert: Send notification
- create_ticket: Create support ticket
- increase_monitoring: Boost monitoring

YELLOW (Auto-Execute + Notify):
- rate_limit_ip: Rate limit for 5 minutes
- flag_account: Flag for review
- trigger_auth_check: Additional authentication

RED (Require Approval):
- lock_account: Lock user account
- block_ip: Block IP permanently
- revoke_api_tokens: Revoke API access
```

**Decision Logic:**
```python
recommend_actions(threat_analysis, anomaly)
→ Check threat severity (high/critical → more aggressive)
→ Check confidence (high confidence → more actions)
→ Check anomaly score (strong anomaly → more actions)
→ Generate actions for each tier
→ Return structured recommendations
```

**Manual Check:**
```python
from backend.agents.response_agent import ResponseAgent

agent = ResponseAgent(sandbox_mode=True)

threat_analysis = {
    "threat_type": "credential_stuffing",
    "confidence": 0.92,
    "severity": "high"
}

anomaly = {
    "source_ip": "203.45.67.89",
    "user_id": "user_123"
}

actions = agent.recommend_actions(threat_analysis, anomaly)
print(f"Green: {len(actions['actions']['green'])}")
print(f"Yellow: {len(actions['actions']['yellow'])}")
print(f"Red: {len(actions['actions']['red'])}")
```

---

### 6. **Action Executor**

**File:** `backend/agents/action_executor.py`

**Purpose:** Executes mitigation actions and tracks them in database

**Execution Flow:**
```python
execute_action(action)
→ Check action tier (green/yellow/red)
→ Green: Execute immediately
→ Yellow: Execute if auto_execute=True, else queue
→ Red: Always queue for approval
→ Store in database
→ Return execution result
```

**Action Types:**
- `log_event`: Store in database
- `send_alert`: Log alert (sandbox mode)
- `rate_limit_ip`: Track rate limit
- `flag_account`: Mark account
- `lock_account`: Queue for approval
- `block_ip`: Queue for approval
- `revoke_api_tokens`: Queue for approval

**Database Schema:**
```sql
actions table:
- action_id (primary key)
- type (action type)
- tier (green/yellow/red)
- status (pending/completed/rejected/rolled_back)
- parameters (JSON)
- executed_at (timestamp)
- rollback_info (JSON)
```

**Manual Check:**
```python
from backend.agents.action_executor import ActionExecutor

executor = ActionExecutor(sandbox_mode=True)

# Green action (auto-executes)
green_action = {
    "id": "test_1",
    "type": "log_event",
    "tier": "green",
    "description": "Log security event"
}
result = executor.execute_action(green_action)
print(f"Status: {result['status']}")  # Should be 'completed'

# Red action (queues)
red_action = {
    "id": "test_2",
    "type": "lock_account",
    "tier": "red",
    "description": "Lock account"
}
result = executor.execute_action(red_action)
print(f"Status: {result['status']}")  # Should be 'pending'

# Get pending
pending = executor.get_pending_actions()
print(f"Pending: {len(pending)}")

# Approve
executor.approve_action("test_2", "admin", "Approved")
```

---

### 7. **Database Layer**

**File:** `backend/utils/database.py`

**Purpose:** Stores logs, threats, and actions in SQLite database

**Tables:**

```sql
logs:
- All processed security logs
- Features extracted for ML
- Timestamps, IPs, actions

alerts:
- Legacy alerts (from Week 1)
- Linked to logs

events:
- Security events timeline
- Aggregated statistics

threats: (NEW - Week 4)
- Complete threat analysis results
- Includes anomaly, analysis, actions
- JSON fields for complex data

actions:
- All executed/pending actions
- Status tracking
- Approval history
- Rollback information
```

**Key Methods:**
```python
insert_log(log) → Store processed log
insert_threat(threat_data) → Store threat analysis
get_threats(limit, severity) → Retrieve threats
get_threat_by_id(alert_id) → Get specific threat
```

**Manual Check:**
```python
from backend.utils.database import SecurityLogDatabase

db = SecurityLogDatabase()

# Insert threat
threat_data = {
    "alert_id": "test_123",
    "timestamp": datetime.now(),
    "severity": "high",
    "confidence": 0.9,
    "threat_type": "DDoS",
    ...
}
db.insert_threat(threat_data)

# Retrieve threats
threats = db.get_threats(limit=10)
print(f"Found {len(threats)} threats")
```

---

### 8. **RAG System**

**File:** `rag/vector_store/chroma_setup.py`

**Purpose:** Vector store for threat intelligence retrieval

**Collections:**
- `threat_intelligence`: MITRE ATT&CK techniques
- `cve_database`: CVE vulnerability descriptions
- `incident_reports`: Historical incident reports

**How It Works:**
```python
1. Documents embedded using sentence-transformers
2. Stored in ChromaDB vector store
3. Query embedded same way
4. Similarity search finds relevant documents
5. Top-K results returned
```

**Manual Check:**
```python
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()

# Search
results = rag.search_threats("brute force attack", n_results=3)
for result in results:
    print(f"Title: {result['metadata']['title']}")
    print(f"Similarity: {result['similarity']}")
```

---

### 9. **Frontend Dashboard**

**Location:** `frontend/`

**Purpose:** Real-time web dashboard for viewing threats and managing actions

**Key Components:**

```
src/
├── pages/
│   ├── Dashboard.tsx          # Main threat feed
│   ├── ThreatDetail.tsx       # Detailed threat view
│   ├── Actions.tsx            # Action management
│   ├── Analytics.tsx          # Statistics
│   └── Compliance.tsx         # Reports
├── components/
│   ├── Layout.tsx             # Main layout with sidebar
│   ├── ThreatCard.tsx        # Threat display card
│   └── StatsCard.tsx         # Statistics card
└── services/
    ├── api.ts                 # REST API client
    └── websocket.ts           # WebSocket client
```

**Data Flow:**
```
User opens dashboard
  ↓
Dashboard.tsx loads
  ↓
Fetches threats via API (api.ts)
  ↓
Connects to WebSocket (websocket.ts)
  ↓
Displays threats in ThreatCard components
  ↓
Real-time updates via WebSocket
```

**Manual Check:**
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

---

## 🔄 Complete Data Flow

### Scenario: Analyzing a Suspicious Log

**Step 1: Log Ingestion**
```
User/System sends log:
POST /api/v1/analyze
{
  "timestamp": "2024-12-01T10:30:00Z",
  "source_ip": "203.45.67.89",
  "action": "login",
  "status": "failed",
  ...
}
```

**Step 2: Orchestrator Receives**
```python
# backend/api/main.py
result = orchestrator.analyze_log(raw_log, return_full_analysis=True)
```

**Step 3: Log Analyzer**
```python
# backend/agents/log_analyzer.py
anomalies, df = self.log_analyzer.detect_anomalies([raw_log])
# Returns: [{"anomaly_score": -0.85, "severity": "high", ...}]
```

**Step 4: Threat Intelligence**
```python
# backend/agents/threat_intelligence_agent.py
threat_analysis = self.threat_intel.analyze_threat(anomaly)
# RAG: Searches vector store for similar threats
# LLM: Generates explanation
# Returns: {"threat_type": "credential_stuffing", "confidence": 0.92, ...}
```

**Step 5: Response Agent**
```python
# backend/agents/response_agent.py
actions = self.response_agent.recommend_actions(threat_analysis, anomaly)
# Returns: {"actions": {"green": [...], "yellow": [...], "red": [...]}}
```

**Step 6: Action Executor**
```python
# backend/agents/action_executor.py
# Execute green actions
for action in actions["green"]:
    executor.execute_action(action)  # Auto-executes

# Queue red actions
for action in actions["red"]:
    executor.execute_action(action)  # Status: pending
```

**Step 7: Database Storage**
```python
# backend/api/main.py
if result.get('threat_detected'):
    db.insert_threat(threat_data)  # Save to database
```

**Step 8: WebSocket Broadcast**
```python
# backend/api/main.py
await manager.broadcast({
    "type": "threat_detected",
    "data": result,
    "timestamp": datetime.now().isoformat()
})
```

**Step 9: Frontend Update**
```typescript
// frontend/src/services/websocket.ts
wsService.on('threat_detected', (event) => {
    // Update dashboard in real-time
    setThreats(prev => [event.data, ...prev])
})
```

**Step 10: Response**
```json
{
  "threat_detected": true,
  "alert_id": "threat_1234567890",
  "anomaly": {...},
  "threat_analysis": {...},
  "recommended_actions": {...},
  "executed_actions": [...],
  "pending_actions": [...]
}
```

---

## 🧪 Manual Testing Guide

### Test 1: System Initialization

**Goal:** Verify all components can be imported and initialized

```python
# Test script
import sys
from pathlib import Path
sys.path.append(str(Path.cwd()))

# Test imports
from backend.agents.log_analyzer import LogAnalyzerAgent
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from backend.agents.response_agent import ResponseAgent
from backend.agents.action_executor import ActionExecutor
from backend.agents.orchestrator import OrchestratorAgent
from backend.utils.database import SecurityLogDatabase
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

print("All imports successful!")

# Initialize components
log_analyzer = LogAnalyzerAgent()
threat_intel = ThreatIntelligenceAgent(use_llm=False)
response_agent = ResponseAgent()
action_executor = ActionExecutor()
orchestrator = OrchestratorAgent()
db = SecurityLogDatabase()
rag = ThreatIntelligenceRAG()

print("All components initialized!")
```

**Expected:** No errors, all components created

---

### Test 2: Training the Model

**Goal:** Train Isolation Forest on benign traffic

```python
from backend.agents.log_analyzer import LogAnalyzerAgent
from backend.utils.data_loader import CICIDSLoader
import pandas as pd

# Load benign data
loader = CICIDSLoader()
df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=10000)

# Filter benign
df = df[df['Label'].str.strip() == 'BENIGN']
print(f"Benign records: {len(df)}")

# Convert to log format
logs = []
for _, row in df.head(5000).iterrows():
    log = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': str(row.get('Source IP', '0.0.0.0')),
        'destination_ip': str(row.get('Destination IP', '0.0.0.0')),
        'user_id': f'user_{hash(str(row.get("Source IP", ""))) % 10000}',
        'action': 'network_flow',
        'resource': f'/network/port_{row.get("Destination Port", 0)}',
        'status': 'success',
        'protocol': 'TCP',
        'port': int(row.get('Destination Port', 0)),
        'bytes_sent': int(row.get('Total Length of Fwd Packets', 0)),
        'bytes_received': int(row.get('Total Length of Bwd Packets', 0)),
        'duration': float(row.get('Flow Duration', 0)) / 1000000.0,
        'metadata': {}
    }
    logs.append(log)

# Train
agent = LogAnalyzerAgent()
stats = agent.train_on_benign_only(logs)
print(f"Training stats: {stats}")
print(f"Model trained: {agent.is_trained}")
```

**Expected:** Model trains successfully, `is_trained = True`

---

### Test 3: Anomaly Detection

**Goal:** Detect anomalies in suspicious logs

```python
# After training (from Test 2)

# Test with suspicious log
suspicious_log = {
    'timestamp': datetime.now().isoformat(),
    'source_ip': '203.45.67.89',
    'destination_ip': '192.168.1.100',
    'user_id': 'user_123',
    'action': 'login',
    'resource': '/api/auth',
    'status': 'failed',
    'protocol': 'TCP',
    'port': 443,
    'bytes_sent': 0,
    'bytes_received': 0,
    'duration': 0.1,
    'metadata': {}
}

anomalies, df = agent.detect_anomalies([suspicious_log])
print(f"Anomalies detected: {len(anomalies)}")
if anomalies:
    print(f"Anomaly score: {anomalies[0]['anomaly_score']}")
    print(f"Severity: {anomalies[0]['severity']}")
```

**Expected:** Anomaly detected with negative score, severity classified

---

### Test 4: Threat Analysis

**Goal:** Get AI explanation of detected threat

```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

# Initialize RAG (if not done)
rag = ThreatIntelligenceRAG()
stats = rag.get_collection_stats()
if stats['threats'] == 0:
    print("Initializing RAG...")
    from rag.vector_store.chroma_setup import (
        create_sample_threat_documents,
        create_sample_cve_documents,
        create_sample_incident_reports
    )
    rag.add_threat_documents(create_sample_threat_documents())
    rag.add_cve_documents(create_sample_cve_documents())
    rag.add_incident_reports(create_sample_incident_reports())

# Analyze threat
agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)  # Test without LLM first

anomaly = {
    "action": "login",
    "status": "failed",
    "anomaly_score": -0.85,
    "severity": "high",
    "source_ip": "203.45.67.89"
}

analysis = agent.analyze_threat(anomaly)
print(f"Threat Type: {analysis['threat_type']}")
print(f"Confidence: {analysis['confidence']}")
print(f"Explanation: {analysis['explanation']}")
print(f"Matched Techniques: {analysis['matched_techniques']}")
```

**Expected:** Threat type identified, explanation generated, techniques matched

---

### Test 5: Action Recommendations

**Goal:** Get recommended mitigation actions

```python
from backend.agents.response_agent import ResponseAgent

agent = ResponseAgent(sandbox_mode=True)

threat_analysis = {
    "threat_type": "credential_stuffing",
    "confidence": 0.92,
    "severity": "high"
}

anomaly = {
    "source_ip": "203.45.67.89",
    "user_id": "user_123"
}

actions = agent.recommend_actions(threat_analysis, anomaly)

print("Green Actions:")
for action in actions['actions']['green']:
    print(f"  - {action['type']}: {action['description']}")

print("\nYellow Actions:")
for action in actions['actions']['yellow']:
    print(f"  - {action['type']}: {action['description']}")

print("\nRed Actions:")
for action in actions['actions']['red']:
    print(f"  - {action['type']}: {action['description']}")
```

**Expected:** Actions recommended for each tier based on threat severity

---

### Test 6: Action Execution

**Goal:** Execute actions and verify they're tracked

```python
from backend.agents.action_executor import ActionExecutor

executor = ActionExecutor(sandbox_mode=True)

# Green action (auto-executes)
green_action = {
    "id": "test_green_1",
    "type": "log_event",
    "tier": "green",
    "description": "Log security event",
    "auto_execute": True
}

result = executor.execute_action(green_action)
print(f"Green action status: {result['status']}")  # Should be 'completed'

# Red action (queues)
red_action = {
    "id": "test_red_1",
    "type": "lock_account",
    "tier": "red",
    "description": "Lock user account",
    "auto_execute": False,
    "parameters": {"user_id": "user_123"}
}

result = executor.execute_action(red_action)
print(f"Red action status: {result['status']}")  # Should be 'pending'

# Check pending
pending = executor.get_pending_actions()
print(f"Pending actions: {len(pending)}")

# Approve red action
approval = executor.approve_action("test_red_1", "admin", "Test approval")
print(f"Approval result: {approval['status']}")

# Check history
history = executor.get_action_history(limit=10)
print(f"Action history: {len(history)}")
```

**Expected:** 
- Green actions execute immediately
- Red actions queue for approval
- Approval works correctly
- History tracks all actions

---

### Test 7: End-to-End Workflow

**Goal:** Test complete pipeline from log to action

```python
from backend.agents.orchestrator import OrchestratorAgent

# Initialize (requires training first - see Test 2)
orchestrator = OrchestratorAgent(sandbox_mode=True)

# Make sure model is trained
if not orchestrator.log_analyzer.is_trained:
    # Train first (use code from Test 2)
    pass

# Analyze suspicious log
test_log = {
    'timestamp': datetime.now().isoformat(),
    'source_ip': '203.45.67.89',
    'destination_ip': '192.168.1.100',
    'user_id': 'user_123',
    'action': 'login',
    'resource': '/api/auth',
    'status': 'failed',
    'protocol': 'TCP',
    'port': 443,
    'bytes_sent': 0,
    'bytes_received': 0,
    'duration': 0.1,
    'metadata': {}
}

result = orchestrator.analyze_log(test_log, return_full_analysis=True)

print("Complete Analysis Result:")
print(f"Threat Detected: {result.get('threat_detected')}")
print(f"Status: {result.get('status')}")

if result.get('threat_detected'):
    print(f"\nAnomaly Score: {result['anomaly']['anomaly_score']}")
    print(f"Threat Type: {result['threat_analysis']['threat_type']}")
    print(f"Confidence: {result['threat_analysis']['confidence']}")
    print(f"Executed Actions: {len(result.get('executed_actions', []))}")
    print(f"Pending Actions: {len(result.get('pending_actions', []))}")
```

**Expected:** Complete analysis with all components working together

---

### Test 8: Database Operations

**Goal:** Verify threats are stored and retrieved correctly

```python
from backend.utils.database import SecurityLogDatabase
from datetime import datetime

db = SecurityLogDatabase()

# Insert threat
threat_data = {
    "alert_id": "test_threat_123",
    "timestamp": datetime.now(),
    "severity": "high",
    "confidence": 0.92,
    "threat_type": "credential_stuffing",
    "description": "Multiple failed login attempts detected",
    "anomaly": {
        "anomaly_score": -0.85,
        "severity": "high",
        "source_ip": "203.45.67.89"
    },
    "status": "detected",
    "threat_analysis": {
        "threat_type": "credential_stuffing",
        "confidence": 0.92,
        "explanation": "Pattern matches credential stuffing attack"
    },
    "recommended_actions": {"actions": {}},
    "executed_actions": [],
    "pending_actions": [],
    "matched_techniques": ["T1110"],
    "affected_resources": ["/api/auth"]
}

alert_id = db.insert_threat(threat_data)
print(f"Threat inserted: {alert_id}")

# Retrieve threats
threats = db.get_threats(limit=10)
print(f"Total threats in DB: {len(threats)}")

# Get specific threat
threat = db.get_threat_by_id("test_threat_123")
if threat:
    print(f"Retrieved threat: {threat['threat_type']}")
```

**Expected:** Threats stored and retrieved successfully

---

### Test 9: API Endpoints

**Goal:** Test REST API endpoints

```bash
# Start server first
cd backend/api
python main.py

# In another terminal:

# 1. Health check
curl http://localhost:8000/health

# 2. Train agent
curl -X POST "http://localhost:8000/api/v1/train?sample_size=5000&benign_only=true"

# 3. Analyze log
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-12-01T10:30:00Z",
    "source_ip": "203.45.67.89",
    "user_id": "user_123",
    "action": "login",
    "resource": "/api/auth",
    "status": "failed",
    "metadata": {}
  }'

# 4. Get threats
curl http://localhost:8000/api/v1/threats

# 5. Get pending actions
curl http://localhost:8000/api/v1/actions/pending

# 6. Get action history
curl http://localhost:8000/api/v1/actions/history
```

**Expected:** All endpoints return valid responses

---

### Test 10: Frontend Integration

**Goal:** Verify dashboard displays data correctly

```bash
# Start backend
cd backend/api
python main.py

# Start frontend (in another terminal)
cd frontend
npm run dev

# Open browser
open http://localhost:3000

# Check:
# 1. Dashboard loads
# 2. Threats appear (if any in database)
# 3. WebSocket connection shows "Live" status
# 4. Click on threat to see details
# 5. Navigate to Actions page
# 6. Navigate to Analytics page
# 7. Generate compliance report
```

**Expected:** Dashboard displays all data, real-time updates work

---

## 📁 Key Files Reference

### Backend Core

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `backend/api/main.py` | Main API server | FastAPI app, endpoints, WebSocket |
| `backend/agents/orchestrator.py` | Workflow coordinator | `OrchestratorAgent` |
| `backend/agents/log_analyzer.py` | Anomaly detection | `LogAnalyzerAgent` |
| `backend/agents/threat_intelligence_agent.py` | Threat explanation | `ThreatIntelligenceAgent` |
| `backend/agents/response_agent.py` | Action recommendations | `ResponseAgent` |
| `backend/agents/action_executor.py` | Action execution | `ActionExecutor` |
| `backend/utils/database.py` | Database operations | `SecurityLogDatabase` |
| `backend/utils/data_loader.py` | Data loading | `CICIDSLoader`, `MITRELoader` |
| `backend/utils/preprocessor.py` | Log preprocessing | `LogPreprocessor` |

### Frontend

| File | Purpose | Key Components |
|------|---------|----------------|
| `frontend/src/App.tsx` | Main app | Router setup |
| `frontend/src/pages/Dashboard.tsx` | Main dashboard | Threat feed |
| `frontend/src/pages/ThreatDetail.tsx` | Threat details | Full analysis view |
| `frontend/src/pages/Actions.tsx` | Action management | Approve/reject UI |
| `frontend/src/services/api.ts` | API client | REST API calls |
| `frontend/src/services/websocket.ts` | WebSocket client | Real-time updates |

### Scripts

| File | Purpose |
|------|---------|
| `scripts/process_real_threats.py` | Process CICIDS attack data |
| `scripts/generate_sample_threats.py` | Generate test threats |
| `scripts/test_system.py` | System health check |
| `scripts/initialize_rag.py` | Initialize RAG system |
| `scripts/run_all_tests.py` | Run all test suites |

### Tests

| File | Purpose |
|------|---------|
| `tests/test_week1.py` | Week 1 foundation tests |
| `tests/test_week2.py` | Week 2 agent tests |
| `tests/test_week3_integration.py` | Week 3 integration tests |
| `tests/test_api.py` | API endpoint tests |
| `tests/test_pipeline.py` | Pipeline tests |

---

## 🔍 How to Manually Verify Each Component

### Verification Checklist

**1. Database Setup**
- [ ] Database file exists: `data/security_logs.db`
- [ ] Tables created: `logs`, `alerts`, `events`, `threats`, `actions`
- [ ] Can insert and retrieve data

**2. RAG System**
- [ ] Vector store initialized: `data/vector_store/`
- [ ] Documents embedded and searchable
- [ ] Can retrieve relevant threats

**3. Log Analyzer**
- [ ] Model can be trained
- [ ] Model persists to disk
- [ ] Can detect anomalies
- [ ] Severity classification works

**4. Threat Intelligence**
- [ ] RAG retrieval works
- [ ] LLM reasoning works (if API key set)
- [ ] Fallback templates work (if no LLM)
- [ ] Confidence scores calculated

**5. Response Agent**
- [ ] Actions classified correctly (green/yellow/red)
- [ ] Recommendations match threat severity
- [ ] Traffic light system works

**6. Action Executor**
- [ ] Green actions auto-execute
- [ ] Red actions queue for approval
- [ ] Actions stored in database
- [ ] Approval workflow works
- [ ] Rollback works

**7. Orchestrator**
- [ ] Coordinates all agents
- [ ] Returns complete analysis
- [ ] Handles errors gracefully

**8. API**
- [ ] All endpoints respond
- [ ] WebSocket connects
- [ ] Real-time updates work
- [ ] CORS enabled

**9. Frontend**
- [ ] Dashboard loads
- [ ] Threats display correctly
- [ ] Real-time updates work
- [ ] All pages functional

**10. End-to-End**
- [ ] Log → Detection → Analysis → Action → Dashboard
- [ ] All components work together
- [ ] Data flows correctly

---

## 🐛 Common Issues & Debugging

### Issue: Model Not Trained
**Symptom:** `Exception: Log Analyzer not trained!`
**Fix:** Call `POST /api/v1/train` first

### Issue: No Threats in Dashboard
**Symptom:** Dashboard shows "No threats detected"
**Fix:** 
1. Check database: `db.get_threats()`
2. Process real threats: `python scripts/process_real_threats.py`
3. Or analyze a log via API

### Issue: RAG Returns Nothing
**Symptom:** `threats: 0` in RAG stats
**Fix:** Run `python scripts/initialize_rag.py`

### Issue: WebSocket Not Connecting
**Symptom:** Dashboard shows "Offline"
**Fix:**
1. Check backend is running
2. Check WebSocket endpoint: `WS /ws`
3. Check browser console for errors

### Issue: LLM Not Working
**Symptom:** "Running in RAG-only mode"
**Fix:**
1. Set `OPENAI_API_KEY` in `.env`
2. Or use template fallback (works without API key)

---

## 📊 Data Flow Diagram (Detailed)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. LOG INGESTION                                            │
│    POST /api/v1/analyze                                     │
│    {timestamp, source_ip, action, status, ...}             │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. ORCHESTRATOR RECEIVES                                    │
│    orchestrator.analyze_log(raw_log)                        │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. LOG ANALYZER AGENT                                       │
│    - Extract ML features                                    │
│    - Scale features                                         │
│    - Run Isolation Forest                                   │
│    - Get anomaly score (-1 to +1)                           │
│    - Classify severity                                      │
│    Output: {anomaly_score: -0.85, severity: "high", ...}  │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼ (if anomaly detected)
┌─────────────────────────────────────────────────────────────┐
│ 4. THREAT INTELLIGENCE AGENT                                │
│    - Create query from anomaly                              │
│    - RAG: Search vector store                               │
│      • MITRE ATT&CK techniques                              │
│      • CVE database                                         │
│      • Historical incidents                                 │
│    - LLM: Generate explanation (if available)               │
│    - Calculate confidence                                   │
│    Output: {threat_type, explanation, confidence, ...}     │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. RESPONSE AGENT                                           │
│    - Check threat severity                                  │
│    - Check confidence                                       │
│    - Classify actions (Traffic Light)                      │
│      • GREEN: Safe actions                                  │
│      • YELLOW: Low-risk actions                             │
│      • RED: High-risk actions                               │
│    Output: {actions: {green: [...], yellow: [...], red: [...]}}│
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. ACTION EXECUTOR                                          │
│    - Execute GREEN actions immediately                      │
│    - Execute YELLOW actions (if auto_execute)               │
│    - Queue RED actions for approval                         │
│    - Store all in database                                  │
│    Output: {executed_actions: [...], pending_actions: [...]}│
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. DATABASE STORAGE                                         │
│    - Insert threat to threats table                         │
│    - Store complete analysis                                │
│    - Track actions                                          │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. WEBSOCKET BROADCAST                                      │
│    - Broadcast threat_detected event                        │
│    - Broadcast action_executed event                        │
│    - Real-time dashboard updates                            │
└────────────────────────┬──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. FRONTEND DASHBOARD                                       │
│    - Receives WebSocket event                               │
│    - Updates threat list                                    │
│    - Displays new threat card                               │
│    - Shows real-time status                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎓 Understanding Key Concepts

### Isolation Forest
- **What:** Unsupervised ML algorithm for anomaly detection
- **How:** Builds random trees, anomalies are isolated faster
- **Output:** Anomaly score (-1 = anomaly, +1 = normal)
- **Why:** Works well for network traffic, no labeled data needed

### RAG (Retrieval-Augmented Generation)
- **What:** Combines vector search with LLM reasoning
- **How:** 
  1. Search vector store for similar threats
  2. Pass context to LLM
  3. LLM generates explanation grounded in retrieved data
- **Why:** More accurate than LLM alone, provides citations

### Traffic Light System
- **What:** Risk-based action classification
- **Green:** Zero risk, auto-execute
- **Yellow:** Low risk, auto-execute + notify
- **Red:** High risk, require approval
- **Why:** Safety mechanism for autonomous systems

### WebSocket
- **What:** Real-time bidirectional communication
- **How:** Persistent connection, server pushes updates
- **Why:** Dashboard updates instantly without polling

---

## 📝 Next Steps for Manual Verification

1. **Start with basics:**
   - Verify database exists and is accessible
   - Check RAG system is initialized
   - Train the model

2. **Test individual components:**
   - Test each agent in isolation
   - Verify inputs/outputs match expectations

3. **Test integration:**
   - Run orchestrator with test logs
   - Verify complete workflow

4. **Test API:**
   - Use curl/Postman to test endpoints
   - Verify responses match expected format

5. **Test frontend:**
   - Open dashboard
   - Verify data displays correctly
   - Test real-time updates

6. **Test with real data:**
   - Run `process_real_threats.py`
   - Verify threats appear in dashboard
   - Check all features work

---

This guide should help you understand and manually verify every part of the system!

