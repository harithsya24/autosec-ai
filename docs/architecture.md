# AutoSec AI - System Architecture

**Version:** 0.1.0  
**Last Updated:** November 2024  
**Status:** Week 1 - Foundation Phase

---

## 🎯 Project Overview

**AutoSec AI** is an autonomous cloud security and threat mitigation agent that uses multi-agent AI systems to detect, analyze, and respond to security threats in real-time.

### Key Objectives
- **Detect** anomalies in system logs using ML models
- **Explain** threats using RAG-powered AI reasoning
- **Recommend** mitigation actions with confidence scoring
- **Execute** safe actions autonomously (with human oversight for risky actions)

---

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER / SOC ANALYST                        │
│                  (Web Dashboard / API)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     FASTAPI BACKEND                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  API Layer  │  │   Agents    │  │ RAG Engine  │        │
│  │  (REST)     │  │ (LangChain) │  │ (ChromaDB)  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Database   │  │ Vector Store│  │  ML Models  │
│  (SQLite)   │  │  (ChromaDB) │  │  (sklearn)  │
└─────────────┘  └─────────────┘  └─────────────┘
```

---

## 📊 Detailed System Flow

### Phase 1: Log Ingestion & Preprocessing
```
Raw Logs → Anonymization → Normalization → Feature Extraction → Storage
    ↓
  [PII Redaction]    [Unified Schema]    [ML Features]    [SQLite DB]
```

### Phase 2: Threat Detection (Week 2)
```
Stored Logs → Anomaly Detection → Scoring → Alert Generation
                     ↓
            [Isolation Forest / Transformer]
                     ↓
              Anomaly Score (0.0-1.0)
```

### Phase 3: Threat Intelligence & Reasoning (Week 2)
```
Detected Anomaly → RAG Retrieval → LLM Analysis → Explanation
                        ↓
               [ChromaDB Vector Search]
                        ↓
            MITRE ATT&CK / CVE / Past Incidents
                        ↓
                  [GPT-4 Reasoning]
                        ↓
             Human-Readable Explanation
```

### Phase 4: Response & Mitigation (Week 3)
```
Threat Analysis → Action Classification → Execution
                         ↓
                  [Traffic Light System]
                   🟢 GREEN (Auto)
                   �� YELLOW (Auto + Notify)
                   🔴 RED (Require Approval)
```

---

## 🔧 Component Details

### 1. **API Layer** (`backend/api/`)
**Technology:** FastAPI  
**Purpose:** RESTful API for all system interactions

**Key Endpoints:**
- `GET /health` - System health check
- `POST /api/v1/logs/ingest` - Ingest security logs
- `GET /api/v1/threats` - Retrieve detected threats
- `POST /api/v1/analyze` - Trigger AI analysis

### 2. **Data Pipeline** (`backend/utils/`)
**Components:**
- **Log Preprocessor**: Anonymizes PII, normalizes format
- **Feature Extractor**: Extracts ML features from logs
- **Data Loader**: Handles various log formats (JSON, CSV, CloudTrail)

**Data Flow:**
1. Raw log received via API
2. PII redaction (IPs → `IP_ADDRESS_1`, emails → `user***@domain.com`)
3. Conversion to unified schema
4. Feature extraction for ML models
5. Storage in database

### 3. **Storage Layer**

#### Database (SQLite)
**Tables:**
- `logs` - All ingested logs (anonymized)
- `alerts` - Generated threat alerts
- `events` - Security events timeline
- `actions` - Mitigation actions taken

#### Vector Store (ChromaDB)
**Collections:**
- `threat_intel` - MITRE ATT&CK techniques
- `cve_database` - CVE descriptions
- `incidents` - Historical incident reports

### 4. **AI Agent System** (Week 2+)

#### Log Analyzer Agent
- **Model:** Isolation Forest / Transformer
- **Input:** Normalized log features
- **Output:** Anomaly score (0.0 = normal, 1.0 = highly suspicious)

#### Threat Intelligence Agent (RAG)
- **Model:** Sentence-Transformers + ChromaDB + GPT-4
- **Input:** Anomaly event description
- **Process:**
  1. Embed query using sentence-transformers
  2. Retrieve top-k similar threats from vector store
  3. Pass context to LLM for reasoning
- **Output:** Threat explanation + matched techniques

#### Response Agent
- **Input:** Threat analysis + confidence score
- **Process:**
  1. Classify threat severity
  2. Determine appropriate actions
  3. Assign action tier (🟢/🟡/🔴)
- **Output:** Recommended mitigation actions

#### Orchestrator Agent
- **Framework:** LangChain / CrewAI
- **Purpose:** Coordinates workflow between agents
- **Flow:** Detection → Retrieval → Analysis → Response

---

## 🗄️ Data Models

### Security Log Schema
```python
{
    "timestamp": datetime,
    "source_ip": str,           # Anonymized
    "user_id": str,             # Anonymized
    "action": str,              # "login", "api_call", "file_access"
    "resource": str,            # Target resource
    "status": str,              # "success", "failed", "denied"
    "metadata": dict            # Additional context
}
```

### Threat Alert Schema
```python
{
    "alert_id": str,
    "severity": str,            # "low", "medium", "high"
    "confidence": float,        # 0.0 to 1.0
    "threat_type": str,         # "credential_stuffing", "privilege_escalation"
    "description": str,         # Human-readable explanation
    "timestamp": datetime,
    "affected_resources": list,
    "matched_techniques": list, # MITRE ATT&CK IDs
    "recommended_actions": list
}
```

---

## 🚦 Traffic Light Action System

### 🟢 GREEN (Auto-Execute)
**Risk:** None  
**Actions:**
- Log the event
- Send email/Slack alert
- Create Jira ticket
- Increase monitoring

### 🟡 YELLOW (Auto-Execute + Notify)
**Risk:** Minimal, reversible  
**Actions:**
- Rate-limit suspicious IP (5 min)
- Flag account for review
- Trigger additional auth checks

### 🔴 RED (Require Approval)
**Risk:** Moderate-High  
**Actions:**
- Lock user account
- Revoke API tokens
- Block IP permanently
- Isolate affected resources

---

## 🔐 Security & Privacy

### Privacy Mode (ON by default)
- All IPs anonymized: `203.45.67.89` → `IP_ADDRESS_1`
- Emails redacted: `john@company.com` → `user***@company.com`
- Usernames hashed: `john_doe` → `USER_A`

### Sandbox Mode (Week 1-2)
- No real infrastructure changes
- All actions are logged but not executed
- Safe for demos and testing

---

## 📈 Development Roadmap

### Week 1: Foundation ✅ (Current)
- [x] FastAPI server
- [x] Data pipeline design
- [ ] Database setup
- [ ] RAG infrastructure
- [ ] Dataset preparation

### Week 2: AI Agents
- [ ] Log Analyzer Agent (anomaly detection)
- [ ] Threat Intelligence Agent (RAG)
- [ ] Response Agent (action recommendations)
- [ ] Agent orchestration

### Week 3: Mitigation & Testing
- [ ] Traffic light action system
- [ ] Autonomous mitigation (sandbox)
- [ ] Integration testing
- [ ] Confidence scoring

### Week 4: Dashboard & Demo
- [ ] React dashboard
- [ ] Real-time threat visualization
- [ ] Compliance reporting
- [ ] Demo preparation

---

## 🔗 Data Sources

### Security Datasets
1. **CICIDS 2017/2018** - Network intrusion detection
2. **AWS CloudTrail** - Cloud access logs
3. **MITRE ATT&CK** - Threat intelligence framework
4. **NVD CVE Database** - Vulnerability descriptions

### Threat Intelligence
- MITRE ATT&CK Techniques (T1078, T1110, etc.)
- CVE Database (National Vulnerability Database)
- Synthetic historical incidents

---

## 📚 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **API** | FastAPI | REST API framework |
| **Agents** | LangChain | Multi-agent orchestration |
| **LLM** | GPT-4 / Claude | Reasoning & explanation |
| **Vector DB** | ChromaDB | RAG retrieval |
| **Embeddings** | Sentence-Transformers | Text embeddings |
| **ML** | scikit-learn | Anomaly detection |
| **Database** | SQLite | Log & alert storage |
| **Frontend** | React (Week 4) | Dashboard UI |

---

## 🎯 Success Metrics

### Week 1
- ✅ API server running
- ✅ Basic endpoints operational
- ⏳ Data pipeline functional
- ⏳ RAG infrastructure ready

### Week 2
- Detection accuracy > 85%
- RAG retrieval relevance > 80%
- Agent response time < 3 seconds

### Week 3
- Zero false positive auto-actions
- All risky actions require approval
- Rollback available for all actions

### Week 4
- End-to-end demo working
- Dashboard visualization complete
- Documentation finalized

---

## 🔄 Next Steps

1. **Complete Day 1:** Finish database and RAG setup
2. **Day 2:** Data acquisition and exploration
3. **Day 3:** Build threat intelligence corpus
4. **Day 4:** Complete preprocessing pipeline
5. **Day 5:** Integration testing

---

**Document Owner:** AutoSec AI Team  
**Review Cycle:** Updated weekly during MVP development
