# 🛡️ AutoSec AI - Autonomous Cloud Security Agent

**An AI-powered multi-agent system for autonomous threat detection, analysis, and mitigation**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Overview

AutoSec AI is a cutting-edge security platform that uses AI agents, RAG (Retrieval-Augmented Generation), and machine learning to autonomously detect and respond to security threats in cloud infrastructure.

### Key Features
- 🔍 **Intelligent Threat Detection** - ML-powered anomaly detection in real-time
- 🧠 **RAG-Powered Explanations** - Context-aware threat analysis using MITRE ATT&CK
- 🚦 **Traffic Light Action System** - Safe autonomous responses with human oversight
- 🔒 **Privacy-First** - Built-in PII anonymization and privacy mode
- 📊 **Real-Time Dashboard** - Visual threat monitoring (Week 4)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- pip package manager
- OpenAI API key (for AI agents)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/autosec-ai.git
cd autosec-ai
```

2. **Create virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
nano .env  # Add your OpenAI API key
```

5. **Run the server**
```bash
cd backend/api
python main.py
```

The API will be available at: http://localhost:8000

---

## 📖 Documentation

- **Interactive API Docs**: http://localhost:8000/docs
- **Architecture**: [docs/architecture.md](docs/architecture.md)
- **Development Plan**: [docs/week1_progress.md](docs/week1_progress.md)

---

## 🧪 Testing

### Run all tests
```bash
bash run_tests.sh
```

### Run specific test file
```bash
pytest tests/test_api.py -v
```

### Run with coverage
```bash
pytest tests/ --cov=backend --cov-report=html
```

---

## 📁 Project Structure

```
autosec-ai/
├── backend/
│   ├── api/
│   │   └── main.py              # FastAPI application
│   ├── agents/                  # AI agents (Week 2)
│   ├── models/                  # ML models (Week 2)
│   └── utils/                   # Helper functions
├── data/
│   ├── raw/                     # Raw datasets
│   ├── processed/               # Processed logs
│   └── chroma_db/               # Vector store
├── rag/
│   ├── embeddings/              # Threat intelligence embeddings
│   └── vector_store/            # RAG infrastructure
├── tests/
│   └── test_api.py              # API tests
├── docs/
│   └── architecture.md          # System architecture
├── notebooks/                   # Jupyter notebooks
├── .env                         # Environment variables (not in git)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🔧 API Endpoints

### Health & Status
- `GET /` - API welcome message
- `GET /health` - Health check with service status
- `GET /api/v1/status` - System statistics

### Log Management
- `POST /api/v1/logs/ingest` - Ingest security logs
- `POST /api/v1/analyze` - Analyze log for threats

### Threat Detection
- `GET /api/v1/threats` - List detected threats
- `GET /api/v1/threats/{alert_id}` - Get threat details

---

## 🗓️ Development Roadmap

### ✅ Week 1: Foundation (Current)
- [x] FastAPI server setup
- [x] Basic API endpoints
- [x] Project architecture
- [x] Test framework
- [ ] Database schema
- [ ] RAG infrastructure

### 📅 Week 2: AI Agents
- [ ] Log Analyzer Agent (anomaly detection)
- [ ] Threat Intelligence Agent (RAG)
- [ ] Response Agent
- [ ] Agent orchestration

### 📅 Week 3: Mitigation
- [ ] Traffic light action system
- [ ] Autonomous mitigation (sandbox)
- [ ] Confidence scoring
- [ ] Integration testing

### 📅 Week 4: Dashboard & Demo
- [ ] React dashboard
- [ ] Real-time visualization
- [ ] Compliance reporting
- [ ] Final demo

---

## 💡 Example Usage

### Ingest a Security Log
```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-11-12T10:30:00",
    "source_ip": "192.168.1.100",
    "user_id": "user_123",
    "action": "login",
    "resource": "/admin",
    "status": "failed",
    "metadata": {"attempts": 5}
  }'
```

### Check System Health
```bash
curl http://localhost:8000/health
```

### Analyze a Log for Threats
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-11-12T10:30:00",
    "source_ip": "203.45.67.89",
    "action": "api_access",
    "resource": "/api/admin/users",
    "status": "success"
  }'
```

---

## 🔒 Security & Privacy

### Privacy Mode (Enabled by Default)
- IP addresses anonymized: `192.168.1.100` → `IP_ADDRESS_1`
- Emails redacted: `user@company.com` → `user***@company.com`
- Usernames hashed: `john_doe` → `USER_A`

### Sandbox Mode (Week 1-2)
- No real infrastructure changes
- All actions are simulated
- Safe for development and demos

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| **API Framework** | FastAPI |
| **AI Agents** | LangChain |
| **LLM** | GPT-4 / Claude |
| **Vector DB** | ChromaDB |
| **Embeddings** | Sentence-Transformers |
| **ML** | scikit-learn |
| **Database** | SQLite |
| **Testing** | pytest |
| **Frontend** | React (Week 4) |

---

## 📊 Data Sources

- **CICIDS 2017/2018** - Network intrusion detection dataset
- **AWS CloudTrail** - Cloud access logs
- **MITRE ATT&CK** - Threat intelligence framework
- **NVD CVE** - Vulnerability database

---

## 🤝 Contributing

This is an academic project for FE524. Contributions during the development phase are welcome!

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `bash run_tests.sh`
5. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Team

**AutoSec AI Development Team**
- Course: FE524
- Semester: Fall 2024
- Institution: [Your University]

---

## 🙏 Acknowledgments

- **MITRE ATT&CK** for threat intelligence framework
- **Canadian Institute for Cybersecurity** for CICIDS dataset
- **FastAPI** and **LangChain** communities
- Course instructor and teaching assistants

---

## 📞 Support

For questions or issues:
- 📧 Email: [your.email@university.edu]
- 📝 Issues: [GitHub Issues](https://github.com/yourusername/autosec-ai/issues)
- 📖 Documentation: [docs/](docs/)

---

## 🎓 Academic Use

This project is developed as part of an academic course. If you use this code for your own academic work, please cite appropriately.

---

**Status:** Week 1 - Foundation Phase  
**Last Updated:** November 2024  
**Version:** 0.1.0
