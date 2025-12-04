# AutoSec AI - Complete Codebase Walkthrough

##  Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Flow](#architecture-flow)
3. [Component-by-Component Breakdown](#component-by-component-breakdown)
4. [Data Flow](#data-flow)
5. [Manual Testing Guide](#manual-testing-guide)
6. [Key Files Reference](#key-files-reference)

---

##  System Overview

**AutoSec AI** is an autonomous security system that:
1. **Detects** threats in network logs using ML
2. **Explains** threats using AI (RAG + LLM)
3. **Recommends** mitigation actions
4. **Executes** safe actions automatically
5. **Displays** everything in a real-time dashboard

---

##  Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    USER / SECURITY ANALYST                  │
│              (Dashboard at http://localhost:3000)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ HTTP Requests / WebSocket
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    FASTAPI BACKEND                          │
│              (backend/api/main.py)                          │
│  - REST API Endpoints                                       │
│  - WebSocket Server                                         │
│  - Request Routing                                          │
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
│                    AI AGENT PIPELINE                        │
│                                                             │
│  Step 1: Log Analyzer Agent                                 │
│  ├─ Input: Raw log data                                     │
│  ├─ Process: Isolation Forest anomaly detection             │
│  └─ Output: Anomaly score + severity                        │
│                                                             │
│  Step 2: Threat Intelligence Agent                          │
│  ├─ Input: Detected anomaly                                 │
│  ├─ Process: RAG retrieval + LLM reasoning                  │
│  └─ Output: Threat explanation + confidence                 │
│                                                             │
│  Step 3: Response Agent                                     │
│  ├─ Input: Threat analysis                                  │
│  ├─ Process: Traffic light classification                   │
│  └─ Output: Action recommendations (Green/Yellow/Red)       │
│                                                             │
│  Step 4: Action Executor                                    │
│  ├─ Input: Recommended actions                              │
│  ├─ Process: Execute green/yellow, queue red                │
│  └─ Output: Execution results                               │
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


## 📊 Data Flow Diagram (Detailed)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. LOG INGESTION                                            │
│    POST /api/v1/analyze                                     │
│    {timestamp, source_ip, action, status, ...}              │
└────────────────────────┬─────────────────────────────────--─┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. ORCHESTRATOR RECEIVES                                    │
│    orchestrator.analyze_log(raw_log)                        │
└────────────────────────┬────────────────────────────────--──┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. LOG ANALYZER AGENT                                       │
│    - Extract ML features                                    │
│    - Scale features                                         │
│    - Run Isolation Forest                                   │
│    - Get anomaly score (-1 to +1)                           │
│    - Classify severity                                      │
│    Output: {anomaly_score: -0.85, severity: "high", ...}    │
└────────────────────────┬───────────────────────────────--───┘
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
│    Output: {threat_type, explanation, confidence, ...}      │
└────────────────────────┬────────────────────────────────--──┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. RESPONSE AGENT                                           │
│    - Check threat severity                                  │
│    - Check confidence                                       │
│    - Classify actions (Traffic Light)                       │
│      • GREEN: Safe actions                                  │
│      • YELLOW: Low-risk actions                             │
│      • RED: High-risk actions                               │
│ Output: {actions: {green: [...], yellow: [...], red: [...]}}│
└────────────────────────┬─────────────────────────────--─────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. ACTION EXECUTOR                                          │
│    - Execute GREEN actions immediately                      │
│    - Execute YELLOW actions (if auto_execute)               │
│    - Queue RED actions for approval                         │
│    - Store all in database                                  │
│    Output: {executed_actions: [...], pending_actions: [...]}│
└────────────────────────┬────────────────────────--──────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. DATABASE STORAGE                                         │
│    - Insert threat to threats table                         │
│    - Store complete analysis                                │
│    - Track actions                                          │
└────────────────────────┬──────────────────────────────────--┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. WEBSOCKET BROADCAST                                      │
│    - Broadcast threat_detected event                        │
│    - Broadcast action_executed event                        │
│    - Real-time dashboard updates                            │
└────────────────────────┬─────────────────────────────────--─┘
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

## Understanding Key Concepts

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
