# Manual Verification Checklist

Use this checklist to manually verify each component of AutoSec AI.

## Prerequisites

- [Y] Python virtual environment activated
- [Y] All dependencies installed (`pip install -r requirements.txt`)
- [Y] CICIDS dataset in `data/raw/cicids/`
- [Y] Backend can start without errors
- [Y] Frontend can start without errors

---

## Phase 1: Core Components

### 1.1 Database Setup

```python
from backend.utils.database import SecurityLogDatabase

db = SecurityLogDatabase()
print(f"Database path: {db.db_path}")
print("Database initialized successfully")
```

**Check:**
- [Y] Database file exists at `data/security_logs.db`
- [Y] No errors during initialization
- [Y] Can insert a test record

---

### 1.2 RAG System

```python
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()
stats = rag.get_collection_stats()
print(f"Threats: {stats['threats']}")
print(f"CVEs: {stats['cves']}")
print(f"Incidents: {stats['incidents']}")

# If empty, initialize
if stats['threats'] == 0:
    from scripts.initialize_rag import main
    main()
```

**Check:**
- [Y] Vector store directory exists
- [Y] Collections have documents (or can be initialized)
- [Y] Can search and retrieve results

---

### 1.3 Log Analyzer

```python
from backend.agents.log_analyzer import LogAnalyzerAgent

agent = LogAnalyzerAgent()
print(f"Initialized: {agent is not None}")
print(f"Trained: {agent.is_trained}")  # Should be False initially
```

**Check:**
- [Y] Agent initializes without errors
- [Y] Model and scaler are created
- [Y] Can call training methods

---

### 1.4 Threat Intelligence Agent

```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()
agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)
print(f"RAG available: {agent.rag is not None}")
print(f"LLM enabled: {agent.use_llm}")
```

**Check:**
- [ ] Agent initializes
- [ ] RAG connection works
- [ ] LLM status is correct (enabled/disabled)

---

### 1.5 Response Agent

```python
from backend.agents.response_agent import ResponseAgent

agent = ResponseAgent(sandbox_mode=True)
print(f"Sandbox mode: {agent.sandbox_mode}")
```

**Check:**
- [ ] Agent initializes
- [ ] Sandbox mode is set correctly

---

### 1.6 Action Executor

```python
from backend.agents.action_executor import ActionExecutor

executor = ActionExecutor(sandbox_mode=True)
print(f"Sandbox mode: {executor.sandbox_mode}")
print(f"Database connected: {executor.db is not None}")
```

**Check:**
- [ ] Executor initializes
- [ ] Database connection works
- [ ] Sandbox mode is set

---

### 1.7 Orchestrator

```python
from backend.agents.orchestrator import OrchestratorAgent

orchestrator = OrchestratorAgent(sandbox_mode=True)
print(f"Log Analyzer: {orchestrator.log_analyzer is not None}")
print(f"Threat Intel: {orchestrator.threat_intel is not None}")
print(f"Response Agent: {orchestrator.response_agent is not None}")
print(f"Action Executor: {orchestrator.action_executor is not None}")
```

**Check:**
- [ ] All agents are initialized
- [ ] No errors during setup

---

## Phase 2: Training & Data

### 2.1 Load Training Data

```python
from backend.utils.data_loader import CICIDSLoader

loader = CICIDSLoader()
df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=1000)
print(f"Loaded {len(df)} records")
print(f"Columns: {list(df.columns[:5])}")
```

**Check:**
- [ ] File loads successfully
- [ ] Data has expected columns
- [ ] Can filter benign traffic

---

### 2.2 Train Model

```python
from backend.agents.log_analyzer import LogAnalyzerAgent
from backend.utils.data_loader import CICIDSLoader

# Load benign data
loader = CICIDSLoader()
df = loader.load_file("Monday-WorkingHours-pcap_ISCX.csv", sample_size=5000)
df = df[df['Label'].str.strip() == 'BENIGN']

# Convert to log format (simplified)
logs = []
for _, row in df.head(3000).iterrows():
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

**Check:**
- [ ] Training completes without errors
- [ ] `is_trained` becomes `True`
- [ ] Model file is created (if persistence enabled)

---

## Phase 3: Detection & Analysis

### 3.1 Anomaly Detection

```python
# After training (from 2.2)

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

anomalies, df = agent.detect_anomalies([test_log])
print(f"Anomalies: {len(anomalies)}")
if anomalies:
    print(f"Score: {anomalies[0]['anomaly_score']}")
    print(f"Severity: {anomalies[0]['severity']}")
```

**Check:**
- [ ] Detection runs without errors
- [ ] Returns anomaly if log is suspicious
- [ ] Anomaly score is negative (indicates anomaly)
- [ ] Severity is classified

---

### 3.2 Threat Analysis

```python
from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()
agent = ThreatIntelligenceAgent(rag=rag, use_llm=False)

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
print(f"Matched: {len(analysis.get('matched_techniques', []))} techniques")
```

**Check:**
- [ ] Analysis completes
- [ ] Threat type is identified
- [ ] Confidence score is between 0 and 1
- [ ] Explanation is generated
- [ ] Techniques are matched (if RAG has data)

---

### 3.3 Action Recommendations

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

# Verify action structure
if actions['actions']['green']:
    green = actions['actions']['green'][0]
    print(f"Green action: {green['type']}, tier: {green['tier']}")
```

**Check:**
- [ ] Actions are recommended
- [ ] Actions have correct tier (green/yellow/red)
- [ ] Actions have descriptions
- [ ] High severity threats get more aggressive actions

---

## Phase 4: Action Execution

### 4.1 Execute Green Action

```python
from backend.agents.action_executor import ActionExecutor

executor = ActionExecutor(sandbox_mode=True)

green_action = {
    "id": "test_green_1",
    "type": "log_event",
    "tier": "green",
    "description": "Log security event",
    "auto_execute": True
}

result = executor.execute_action(green_action)
print(f"Status: {result['status']}")
print(f"Action ID: {result.get('action_id')}")
```

**Check:**
- [ ] Action executes immediately
- [ ] Status is "completed"
- [ ] Action ID is returned
- [ ] Stored in database

---

### 4.2 Queue Red Action

```python
red_action = {
    "id": "test_red_1",
    "type": "lock_account",
    "tier": "red",
    "description": "Lock user account",
    "auto_execute": False,
    "parameters": {"user_id": "user_123"}
}

result = executor.execute_action(red_action)
print(f"Status: {result['status']}")  # Should be 'pending'
```

**Check:**
- [ ] Action is queued (status = "pending")
- [ ] Appears in pending list
- [ ] Not executed automatically

---

### 4.3 Approve Action

```python
pending = executor.get_pending_actions()
print(f"Pending: {len(pending)}")

if pending:
    action_id = pending[0]['action_id']
    approval = executor.approve_action(
        action_id,
        "test_approver",
        "Test approval"
    )
    print(f"Approval status: {approval['status']}")
```

**Check:**
- [ ] Pending actions are retrieved
- [ ] Approval works
- [ ] Action is executed after approval
- [ ] Status changes to "completed"

---

### 4.4 Action History

```python
history = executor.get_action_history(limit=10)
print(f"History: {len(history)} actions")

if history:
    latest = history[0]
    print(f"Latest: {latest['type']}, Status: {latest['status']}")
```

**Check:**
- [ ] History is retrieved
- [ ] Contains executed actions
- [ ] Has correct status
- [ ] Includes timestamps

---

## Phase 5: Orchestrator Integration

### 5.1 Complete Workflow

```python
from backend.agents.orchestrator import OrchestratorAgent

orchestrator = OrchestratorAgent(sandbox_mode=True)

# Ensure model is trained (from 2.2)
if not orchestrator.log_analyzer.is_trained:
    # Train first
    pass

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

# Verify structure
print(f"Threat detected: {result.get('threat_detected')}")
print(f"Has anomaly: {'anomaly' in result}")
print(f"Has threat_analysis: {'threat_analysis' in result}")
print(f"Has recommended_actions: {'recommended_actions' in result}")
print(f"Has executed_actions: {'executed_actions' in result}")
print(f"Has pending_actions: {'pending_actions' in result}")
```

**Check:**
- [ ] Complete workflow runs
- [ ] All expected fields are present
- [ ] No errors during execution
- [ ] Results are structured correctly

---

## Phase 6: API Testing

### 6.1 Start Server

```bash
cd backend/api
python main.py
```

**Check:**
- [ ] Server starts without errors
- [ ] Shows startup messages
- [ ] Health endpoint works: `curl http://localhost:8000/health`

---

### 6.2 Train via API

```bash
curl -X POST "http://localhost:8000/api/v1/train?sample_size=5000&benign_only=true"
```

**Check:**
- [ ] Training starts
- [ ] Returns success status
- [ ] Model is trained (check via status endpoint)

---

### 6.3 Analyze via API

```bash
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
```

**Check:**
- [ ] Request is accepted
- [ ] Analysis completes
- [ ] Response contains all expected fields
- [ ] Threat is saved to database (if detected)

---

### 6.4 Get Threats

```bash
curl http://localhost:8000/api/v1/threats
```

**Check:**
- [ ] Returns list of threats
- [ ] Threats have all required fields
- [ ] Can filter by severity (if implemented)

---

### 6.5 Action Management

```bash
# Get pending
curl http://localhost:8000/api/v1/actions/pending

# Approve (replace {id} with actual ID)
curl -X POST http://localhost:8000/api/v1/actions/{id}/approve \
  -H "Content-Type: application/json" \
  -d '{"approver": "admin", "reason": "Test"}'

# Get history
curl http://localhost:8000/api/v1/actions/history
```

**Check:**
- [ ] Pending actions are returned
- [ ] Approval works
- [ ] History is retrieved
- [ ] All endpoints respond correctly

---

## Phase 7: Frontend Testing

### 7.1 Start Frontend

```bash
cd frontend
npm install  # First time only
npm run dev
```

**Check:**
- [ ] Frontend starts without errors
- [ ] Opens at http://localhost:3000
- [ ] No console errors

---

### 7.2 Dashboard

**Check:**
- [ ] Dashboard page loads
- [ ] Stats cards display (may show 0 initially)
- [ ] System status shows agent states
- [ ] WebSocket connection shows "Live" (if backend running)

---

### 7.3 Threat Display

**Check:**
- [ ] Threats appear in feed (if any in database)
- [ ] Threat cards show correct information
- [ ] Severity badges are color-coded
- [ ] Confidence scores display
- [ ] "View Details" button works

---

### 7.4 Threat Detail Page

**Check:**
- [ ] Clicking threat opens detail page
- [ ] Shows AI reasoning chain
- [ ] Shows retrieved context
- [ ] Shows confidence breakdown
- [ ] Shows action recommendations
- [ ] Can approve/reject actions

---

### 7.5 Actions Page

**Check:**
- [ ] Pending actions tab shows queued actions
- [ ] Action history tab shows executed actions
- [ ] Can approve actions
- [ ] Can reject actions
- [ ] Can rollback completed actions

---

### 7.6 Analytics Page

**Check:**
- [ ] Statistics cards display
- [ ] Charts render correctly
- [ ] Data is accurate
- [ ] Can see trends over time

---

### 7.7 Compliance Page

**Check:**
- [ ] Can select report type
- [ ] Can set date range
- [ ] Can generate report
- [ ] Report displays correctly
- [ ] Can download report

---

## Phase 8: Real Data Processing

### 8.1 Process Real Threats

```bash
python scripts/process_real_threats.py
```

**Check:**
- [ ] Script runs without errors
- [ ] Trains on benign data
- [ ] Processes attack files
- [ ] Detects threats
- [ ] Stores threats in database
- [ ] Shows summary statistics

---

### 8.2 Verify in Dashboard

**Check:**
- [ ] Threats appear in dashboard
- [ ] Real threat types are shown
- [ ] Analysis is complete
- [ ] Actions are recommended
- [ ] Can view details

---

## Phase 9: WebSocket Testing

### 9.1 Real-Time Updates

**Steps:**
1. Open dashboard
2. Open browser console (F12)
3. Analyze a log via API
4. Watch for WebSocket message

**Check:**
- [ ] WebSocket connects
- [ ] Threat appears in dashboard immediately
- [ ] No page refresh needed
- [ ] Connection status shows "Live"

---

## Phase 10: End-to-End Verification

### 10.1 Complete Flow

**Steps:**
1. Start backend: `cd backend/api && python main.py`
2. Start frontend: `cd frontend && npm run dev`
3. Train model: `POST /api/v1/train`
4. Process real threats: `python scripts/process_real_threats.py`
5. Open dashboard: http://localhost:3000
6. View threats
7. Click on threat
8. Approve/reject actions
9. Check analytics
10. Generate compliance report

**Check:**
- [ ] All steps complete successfully
- [ ] Data flows correctly
- [ ] No errors in console
- [ ] All features work

---

## Common Verification Patterns

### Pattern 1: Check Component Initialization

```python
component = ComponentClass()
assert component is not None
print("Component initialized")
```

### Pattern 2: Check Method Execution

```python
result = component.method(input_data)
assert result is not None
assert 'expected_field' in result
print(f"Method executed: {result}")
```

### Pattern 3: Check Database

```python
db = SecurityLogDatabase()
data = db.get_threats(limit=1)
assert isinstance(data, list)
print(f"Database accessible: {len(data)} records")
```

### Pattern 4: Check API

```bash
response=$(curl -s http://localhost:8000/health)
echo $response | grep -q "status" && echo "API working" || echo "API error"
```

---

## Debugging Tips

1. **Check Logs:** Look at console output for errors
2. **Verify Paths:** Ensure file paths are correct
3. **Check Dependencies:** Verify all packages installed
4. **Test Isolation:** Test components individually first
5. **Use Print Statements:** Add prints to trace execution
6. **Check Database:** Query database directly to verify data
7. **Browser Console:** Check frontend console for errors
8. **Network Tab:** Check API requests in browser dev tools

---

## Success Criteria

System is working correctly if:

- [ ] All components initialize without errors
- [ ] Model can be trained
- [ ] Anomalies are detected
- [ ] Threats are analyzed
- [ ] Actions are recommended
- [ ] Actions are executed/queued correctly
- [ ] Data is stored in database
- [ ] API endpoints respond correctly
- [ ] Dashboard displays data
- [ ] Real-time updates work
- [ ] End-to-end flow completes

---

Use this checklist to systematically verify every component!




