# Quick Reference Guide

## 🚀 Quick Start

### Start Backend
```bash
cd backend/api
python main.py
# Server runs on http://localhost:8000
```

### Start Frontend
```bash
cd frontend
npm run dev
# Dashboard opens at http://localhost:3000
```

### Train Model
```bash
curl -X POST "http://localhost:8000/api/v1/train?sample_size=5000&benign_only=true"
```

### Process Real Threats
```bash
python scripts/process_real_threats.py
```

---

## 📁 File Structure Quick Reference

```
autosec-ai/
├── backend/
│   ├── api/
│   │   └── main.py              # FastAPI server, endpoints, WebSocket
│   ├── agents/
│   │   ├── orchestrator.py      # Coordinates all agents
│   │   ├── log_analyzer.py      # ML anomaly detection
│   │   ├── threat_intelligence_agent.py  # RAG + LLM explanation
│   │   ├── response_agent.py    # Action recommendations
│   │   └── action_executor.py   # Execute actions
│   └── utils/
│       ├── database.py          # SQLite operations
│       ├── data_loader.py       # Load CICIDS data
│       └── preprocessor.py     # Log preprocessing
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.tsx    # Main threat feed
│       │   ├── ThreatDetail.tsx # Detailed view
│       │   └── Actions.tsx      # Action management
│       └── services/
│           ├── api.ts           # REST API client
│           └── websocket.ts     # WebSocket client
├── rag/
│   └── vector_store/
│       └── chroma_setup.py      # RAG vector store
└── scripts/
    ├── process_real_threats.py   # Process CICIDS attacks
    └── initialize_rag.py        # Initialize RAG system
```

---

## 🔄 Code Flow (Step by Step)

### When a log is analyzed:

**1. API receives request**
```python
# backend/api/main.py
@app.post("/api/v1/analyze")
async def analyze_log(log: LogEvent):
    result = orchestrator.analyze_log(log.dict())
```

**2. Orchestrator coordinates**
```python
# backend/agents/orchestrator.py
def analyze_log(self, raw_log):
    # Step 1: Detect anomalies
    anomalies = self.log_analyzer.detect_anomalies([raw_log])
    
    # Step 2: Analyze threat (if anomaly found)
    threat_analysis = self.threat_intel.analyze_threat(anomaly)
    
    # Step 3: Recommend actions
    actions = self.response_agent.recommend_actions(...)
    
    # Step 4: Execute actions
    executed = self.action_executor.execute_actions(...)
```

**3. Log Analyzer detects**
```python
# backend/agents/log_analyzer.py
def detect_anomalies(self, logs):
    features = self.preprocessor.extract_features(logs)
    scores = self.model.decision_function(features)
    # Returns: anomaly_score, severity
```

**4. Threat Intelligence explains**
```python
# backend/agents/threat_intelligence_agent.py
def analyze_threat(self, anomaly):
    # RAG: Search vector store
    context = self.rag.search_threats(query)
    
    # LLM: Generate explanation
    explanation = self.llm.generate(context, anomaly)
    
    # Returns: threat_type, explanation, confidence
```

**5. Response Agent recommends**
```python
# backend/agents/response_agent.py
def recommend_actions(self, threat_analysis, anomaly):
    # Classify by tier
    green = [...]  # Safe actions
    yellow = [...] # Low-risk actions
    red = [...]    # High-risk actions
```

**6. Action Executor executes**
```python
# backend/agents/action_executor.py
def execute_action(self, action):
    if action['tier'] == 'green':
        # Execute immediately
    elif action['tier'] == 'red':
        # Queue for approval
```

**7. Database stores**
```python
# backend/utils/database.py
db.insert_threat(threat_data)
```

**8. WebSocket broadcasts**
```python
# backend/api/main.py
await manager.broadcast({
    "type": "threat_detected",
    "data": result
})
```

**9. Frontend updates**
```typescript
// frontend/src/services/websocket.ts
wsService.on('threat_detected', (event) => {
    setThreats(prev => [event.data, ...prev])
})
```

---

## 🔑 Key Classes & Methods

### OrchestratorAgent
```python
orchestrator = OrchestratorAgent(sandbox_mode=True)
result = orchestrator.analyze_log(log_dict)
```

### LogAnalyzerAgent
```python
agent = LogAnalyzerAgent()
agent.train_on_benign_only(benign_logs)
anomalies, df = agent.detect_anomalies(logs)
```

### ThreatIntelligenceAgent
```python
agent = ThreatIntelligenceAgent(rag=rag, use_llm=True)
analysis = agent.analyze_threat(anomaly)
```

### ResponseAgent
```python
agent = ResponseAgent(sandbox_mode=True)
actions = agent.recommend_actions(threat_analysis, anomaly)
```

### ActionExecutor
```python
executor = ActionExecutor(sandbox_mode=True)
result = executor.execute_action(action)
pending = executor.get_pending_actions()
executor.approve_action(action_id, approver, reason)
```

### SecurityLogDatabase
```python
db = SecurityLogDatabase()
db.insert_threat(threat_data)
threats = db.get_threats(limit=10)
threat = db.get_threat_by_id(alert_id)
```

---

## 🧪 Testing Commands

### Test Individual Components
```python
# Test log analyzer
python -c "from backend.agents.log_analyzer import LogAnalyzerAgent; print('OK')"

# Test database
python -c "from backend.utils.database import SecurityLogDatabase; db = SecurityLogDatabase(); print('OK')"
```

### Test API Endpoints
```bash
# Health
curl http://localhost:8000/health

# Train
curl -X POST "http://localhost:8000/api/v1/train?sample_size=5000"

# Analyze
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "2024-12-01T10:30:00Z", "source_ip": "1.2.3.4", ...}'

# Get threats
curl http://localhost:8000/api/v1/threats
```

### Run Test Suites
```bash
# Week 1 tests
python -m pytest tests/test_week1.py -v

# Week 2 tests
python -m pytest tests/test_week2.py -v

# Week 3 tests
python -m pytest tests/test_week3_integration.py -v

# All tests
python scripts/run_all_tests.py
```

---

## 📊 Data Structures

### Log Format
```python
{
    "timestamp": "2024-12-01T10:30:00Z",
    "source_ip": "203.45.67.89",
    "destination_ip": "192.168.1.100",
    "user_id": "user_123",
    "action": "login",
    "resource": "/api/auth",
    "status": "failed",
    "protocol": "TCP",
    "port": 443,
    "bytes_sent": 0,
    "bytes_received": 0,
    "duration": 0.1,
    "metadata": {}
}
```

### Anomaly Result
```python
{
    "anomaly_score": -0.85,  # Negative = anomaly
    "severity": "high",       # low/medium/high/critical
    "source_ip": "203.45.67.89",
    "timestamp": "2024-12-01T10:30:00Z"
}
```

### Threat Analysis
```python
{
    "threat_type": "credential_stuffing",
    "confidence": 0.92,
    "explanation": "Pattern matches...",
    "matched_techniques": ["T1110", "T1078"],
    "severity": "high"
}
```

### Action Recommendation
```python
{
    "actions": {
        "green": [
            {"id": "...", "type": "log_event", "tier": "green", ...}
        ],
        "yellow": [
            {"id": "...", "type": "rate_limit_ip", "tier": "yellow", ...}
        ],
        "red": [
            {"id": "...", "type": "lock_account", "tier": "red", ...}
        ]
    }
}
```

---

## 🔧 Common Tasks

### Initialize RAG System
```python
python scripts/initialize_rag.py
```

### Process Real CICIDS Data
```python
python scripts/process_real_threats.py
```

### Generate Sample Threats
```python
python scripts/generate_sample_threats.py
```

### Check System Health
```python
python scripts/test_system.py
```

### View Database
```bash
sqlite3 data/security_logs.db
.tables
SELECT * FROM threats LIMIT 5;
```

---

## 🐛 Quick Debugging

### Check if model is trained
```python
from backend.agents.log_analyzer import LogAnalyzerAgent
agent = LogAnalyzerAgent()
print(agent.is_trained)  # Should be True
```

### Check RAG status
```python
from rag.vector_store.chroma_setup import ThreatIntelligenceRAG
rag = ThreatIntelligenceRAG()
stats = rag.get_collection_stats()
print(stats)  # Should show document counts
```

### Check database
```python
from backend.utils.database import SecurityLogDatabase
db = SecurityLogDatabase()
threats = db.get_threats(limit=5)
print(f"Threats in DB: {len(threats)}")
```

### Check WebSocket
```javascript
// In browser console
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', e.data);
```

---

## 📝 Important Notes

1. **Training Required:** Model must be trained before detection
2. **RAG Initialization:** Run `initialize_rag.py` if RAG is empty
3. **Sandbox Mode:** All actions are simulated (no real changes)
4. **LLM Optional:** System works without OpenAI API key (uses templates)
5. **Database Path:** Uses absolute path, works from any directory

---

## 🎯 Typical Workflow

1. **Setup**
   ```bash
   python scripts/initialize_rag.py
   ```

2. **Train**
   ```bash
   curl -X POST "http://localhost:8000/api/v1/train?sample_size=5000"
   ```

3. **Process Data**
   ```bash
   python scripts/process_real_threats.py
   ```

4. **View Results**
   - Open dashboard: http://localhost:3000
   - Or check API: `curl http://localhost:8000/api/v1/threats`

---

This is your quick reference for understanding and using the system!

