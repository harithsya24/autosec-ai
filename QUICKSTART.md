# AutoSec AI - Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### Step 1: Backend Setup

```bash
# Navigate to backend
cd backend/api

# Install dependencies (if not already done)
pip install -r ../../requirements.txt

# Start the FastAPI server
python main.py
```

Backend will be available at: `http://localhost:8000`

### Step 2: Train the Agent

```bash
# Train the agent on benign traffic
curl -X POST "http://localhost:8000/api/v1/train?sample_size=10000&benign_only=true"
```

Wait for training to complete (~30 seconds).

### Step 3: Frontend Setup

```bash
# In a new terminal, navigate to frontend
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

Dashboard will be available at: `http://localhost:3000`

### Step 4: Test the System

**Option A: Via Dashboard**
1. Open `http://localhost:3000`
2. Navigate to Dashboard
3. System is ready!

**Option B: Via API**
```bash
# Analyze a suspicious log
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-12-01T10:30:00Z",
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
  }'
```

Watch the threat appear in real-time on the dashboard!

## 📋 What's Available

### Dashboard Pages

1. **Dashboard** (`/`) - Real-time threat feed
2. **Actions** (`/actions`) - Approve/reject actions
3. **Analytics** (`/analytics`) - Statistics and trends
4. **Compliance** (`/compliance`) - Generate reports

### API Endpoints

- `GET /health` - Health check
- `POST /api/v1/train` - Train the agent
- `POST /api/v1/analyze` - Analyze a log
- `GET /api/v1/actions/pending` - Get pending actions
- `POST /api/v1/actions/{id}/approve` - Approve action
- `POST /api/v1/compliance/reports` - Generate report
- `WS /ws` - WebSocket for real-time updates

## 🎯 Demo Flow

1. **Show Dashboard** - Explain real-time threat stream
2. **Trigger Threat** - Analyze a suspicious log
3. **Show Real-Time Update** - Threat appears instantly
4. **View Threat Detail** - Show AI reasoning and RAG citations
5. **Approve Action** - Demonstrate approval workflow
6. **Generate Report** - Create compliance report

## 🐛 Troubleshooting

### Backend Issues

**Port already in use:**
```bash
# Change port in .env or environment variable
export API_PORT=8001
```

**Agent not trained:**
```bash
# Make sure to train first
curl -X POST "http://localhost:8000/api/v1/train?sample_size=10000&benign_only=true"
```

### Frontend Issues

**Dependencies not installed:**
```bash
cd frontend
npm install
```

**Port conflict:**
```bash
# Edit vite.config.ts to change port
```

**WebSocket not connecting:**
- Check backend is running
- Check CORS settings
- Check browser console for errors

## 📚 Documentation

- [Week 4 Implementation](./docs/WEEK4_IMPLEMENTATION.md)
- [Week 3 Complete](./docs/WEEK3_COMPLETE.md)
- [Architecture](./docs/architecture.md)
- [Frontend README](./frontend/README.md)

## ✅ System Status

- ✅ Week 1: Foundation - Complete
- ✅ Week 2: AI Agents - Complete
- ✅ Week 3: Action Execution - Complete
- ✅ Week 4: Dashboard & Demo - Complete

**MVP Status:** 🎉 **100% Complete!**


