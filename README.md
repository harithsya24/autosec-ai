# AutoSec AI

> **Autonomous Cloud Security with Multi-Agent AI**

AutoSec AI is an intelligent security orchestration system that uses specialized AI agents to detect, analyze, and respond to security threats in real-time. Built with machine learning, retrieval-augmented generation (RAG), and large language models (LLMs), it provides autonomous threat mitigation with human oversight.

## Key Features

### Multi-Agent Architecture
- **Log Analyzer Agent**: ML-based anomaly detection using Isolation Forest
- **Threat Intelligence Agent**: RAG-powered context retrieval from MITRE ATT&CK
- **Response Agent**: Intelligent action classification with risk assessment
- **Action Executor**: Safe, reversible action execution with rollback capability

### Traffic Light Safety System
- **GREEN**: Auto-executed low-risk actions (logging, rate limiting)
- **YELLOW**: Medium-risk actions with optional auto-execution
- **RED**: High-risk actions requiring human approval (IP blocking, account disabling)

### Real-Time Threat Detection
- Continuous network traffic monitoring
- Multi-factor confidence scoring
- MITRE ATT&CK technique mapping
- Live WebSocket updates to dashboard

### Compliance & Reporting
- Automated SOC2, GDPR, and HIPAA reports
- LLM-generated compliance narratives
- Comprehensive audit trails
- Analytics and trend visualization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Dashboard                        │
│              (React + WebSocket + Tailwind)                  │
└─────────────────────┬───────────────────────────────────────┘
                      │ WebSocket / REST API
┌─────────────────────▼───────────────────────────────────────┐
│                   FastAPI Backend                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Log Analyzer │  │  Threat Intel │  │   Response   │      │
│  │   (ML/IF)    │─▶│   (RAG/LLM)  │─▶│    (LLM)     │      │
│  └──────────────┘  └──────────────┘  └──────┬───────┘      │
│                                              │               │
│  ┌──────────────────────────────────────────▼───────┐      │
│  │          Action Executor (Sandbox)               │      │
│  └──────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│         SQLite Database + Vector Store (ChromaDB)            │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+
- OpenAI API key (for LLM features)
- CICIDS2017 dataset (optional, for training)

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/autosec-ai.git
cd autosec-ai
```

### 2. Backend Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Set OpenAI API key
export OPENAI_API_KEY=your_key_here

# Start backend server
cd backend/api
python main.py
```

Backend will be available at `http://localhost:8000`

### 3. Train the Agent

```bash
# Option A: Via Python
python -c "
from backend.agents.orchestrator import OrchestratorAgent
from backend.utils.data_loader import CICIDSLoader

orchestrator = OrchestratorAgent(sandbox_mode=True)
loader = CICIDSLoader(data_dir='data/raw/cicids')
df = loader.load_file('Monday-WorkingHours-pcap_ISCX.csv', sample_size=10000)
orchestrator.log_analyzer.train(df.to_dict('records'))
print('Agent trained successfully!')
"

# Option B: Via API
curl -X POST http://localhost:8000/api/v1/train \
  -H "Content-Type: application/json" \
  -d '{"sample_size": 10000}'
```

### 4. Frontend Setup

```bash
# Install dependencies
cd frontend
npm install

# Start development server
npm run dev
```

Dashboard will be available at `http://localhost:3000`

## Demo Mode

AutoSec AI includes a simulation mode for demonstrations and testing:

1. Navigate to the dashboard at `http://localhost:3000`
2. Click **"Start Demo (5 min)"** in the Demo Mode panel
3. Watch as realistic threats are simulated in real-time
4. Observe the system detect, analyze, and respond to threats
5. Explore threat details, RAG context, and action recommendations

### Demo Threats Include:
- Port Scanning (LOW)
- API Abuse (MEDIUM)
- Suspicious Login Attempts (MEDIUM)
- Credential Stuffing (HIGH)
- Data Exfiltration (HIGH)
- Privilege Escalation (CRITICAL)
- Insider Threats (CRITICAL)

## Usage

### Detect Threats

```python
from backend.agents.orchestrator import OrchestratorAgent

orchestrator = OrchestratorAgent(sandbox_mode=True)
log_entry = {
    "source_ip": "192.168.1.100",
    "destination_port": 22,
    "protocol": "TCP",
    "timestamp": "2024-01-15 10:30:00"
}

threat = orchestrator.process_log(log_entry)
print(f"Threat detected: {threat.severity} - {threat.description}")
```

### Generate Compliance Reports

```python
from backend.agents.compliance_agent import ComplianceAgent

agent = ComplianceAgent()
report = agent.generate_report(
    report_type="SOC2",
    start_date="2024-01-01",
    end_date="2024-01-31"
)
print(report.report_text)
```

### Execute Actions (Sandbox)

```python
from backend.agents.action_executor import ActionExecutor

executor = ActionExecutor(sandbox_mode=True)
result = executor.execute_action({
    "action_type": "block_ip",
    "parameters": {"ip_address": "10.0.0.50"},
    "risk_level": "RED"
})
print(f"Action executed: {result.success}")
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# OpenAI API
OPENAI_API_KEY=your_key_here

# Database
DATABASE_PATH=data/security_logs.db

# Vector Store
CHROMA_PATH=data/chroma_db

# API Settings
API_HOST=0.0.0.0
API_PORT=8000

# Feature Flags
ENABLE_AUTO_EXECUTION=true
ENABLE_RAG=true
SANDBOX_MODE=true
```

### Agent Configuration

Edit `config/agent_config.yaml`:

```yaml
log_analyzer:
  model: isolation_forest
  contamination: 0.1
  threshold: 0.7

threat_intelligence:
  embedding_model: text-embedding-3-small
  llm_model: gpt-4
  max_context_docs: 5

response_agent:
  auto_execute_threshold: 0.8
  require_approval_threshold: 0.6
```

## API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Key Endpoints

```
POST   /api/v1/logs              - Submit log entry
GET    /api/v1/threats           - List detected threats
GET    /api/v1/threats/{id}      - Get threat details
POST   /api/v1/actions/{id}      - Approve/reject action
POST   /api/v1/train             - Train ML model
GET    /api/v1/agent/status      - Check agent status
POST   /api/v1/compliance/report - Generate report
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=html

# Run specific test suite
pytest tests/test_agents.py

# Run frontend tests
cd frontend
npm test
```

## Documentation

- **Quick Reference** - Command cheatsheet
- **Codebase Walkthrough** - Architecture deep dive
- **Demo Script** - Presentation guide
- **API Documentation** - Interactive API docs

## Roadmap

### Phase 1 (Current)
- Multi-agent orchestration
- ML-based anomaly detection
- RAG threat intelligence
- Traffic light safety system
- Real-time dashboard

### Phase 2 (Next)
- Cloud integrations (AWS, GCP, Azure)
- Custom threat intelligence feeds
- Advanced ML models (GNN, Transformers)
- Multi-tenancy support
- Mobile app

### Phase 3 (Future)
- Reinforcement learning optimization
- Federated learning for privacy
- Zero-trust architecture integration
- Blockchain audit trail
- AI red team simulation

## Contributing

Contributions are welcome! Please see our Contributing Guide for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **CICIDS2017** dataset by Canadian Institute for Cybersecurity
- **MITRE ATT&CK** framework for threat intelligence
- **OpenAI** for GPT models
- **ChromaDB** for vector storage
- **FastAPI** and **React** communities

## Contact

- **Project Lead**: Your Name
- **Email**: your.email@example.com
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

## Disclaimer

AutoSec AI is designed for demonstration and educational purposes. While the system includes safety mechanisms and sandbox mode, it should be thoroughly tested and validated before use in production environments. Always have human oversight for critical security decisions.

---

**Built with care by security professionals, for security professionals.**