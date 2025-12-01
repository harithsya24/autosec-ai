# AutoSec AI - Demo Script

## Overview

This document provides a step-by-step guide for demonstrating the AutoSec AI threat detection and mitigation system. The demo showcases real-time threat detection, AI-powered analysis, and autonomous response capabilities.

## Pre-Demo Setup

### 1. Start Backend Server

```bash
cd backend/api
python main.py
```

**Verify:**
- Server running on `http://localhost:8000`
- API docs available at `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### 2. Train the Agent (if not already trained)

```bash
# From project root
python -c "
from backend.agents.orchestrator import OrchestratorAgent
from backend.utils.data_loader import CICIDSLoader
from pathlib import Path

orchestrator = OrchestratorAgent(sandbox_mode=True)
loader = CICIDSLoader(data_dir='data/raw/cicids')
df = loader.load_file('Monday-WorkingHours-pcap_ISCX.csv', sample_size=10000)
logs = df.to_dict('records')
orchestrator.log_analyzer.train(logs)
print('Agent trained successfully!')
"
```

Or use the API:
```bash
curl -X POST http://localhost:8000/api/v1/train \
  -H "Content-Type: application/json" \
  -d '{"sample_size": 10000}'
```

### 3. Start Frontend Dashboard

```bash
cd frontend
npm install  # If first time
npm run dev
```

**Verify:**
- Dashboard available at `http://localhost:3000`
- WebSocket connection established (check browser console)

## Demo Flow (5-Minute Presentation)

### Minute 0-1: Introduction & System Overview

**What to Show:**
1. **Dashboard Overview**
   - Point out the empty dashboard (no threats yet)
   - Explain the four key metrics:
     - Events Detected
     - High Priority
     - Auto-Executed
     - Pending Approval

2. **System Status**
   - Show all agents are operational
   - Explain the multi-agent architecture:
     - Log Analyzer (ML-based detection)
     - Threat Intelligence (RAG + LLM)
     - Response Agent (Action classification)
     - Action Executor (Safe execution)

3. **Demo Mode Controls**
   - Point to the "Demo Mode - Threat Simulation" panel
   - Explain this is a sandbox environment
   - Show the simulation controls

**What to Say:**
> "AutoSec AI is an autonomous cloud security system that uses AI agents to detect, analyze, and respond to security threats in real-time. Right now, the system is monitoring but hasn't detected any threats. Let me demonstrate how it works by simulating realistic attack scenarios."

---

### Minute 1-2: Start Demo Mode & First Threats

**Action:**
1. Click **"Start Demo (5 min)"** button
2. Watch the status change to "ACTIVE"
3. Wait for first threat to appear (should be within 30 seconds)

**What to Show:**
1. **First Threat Appears**
   - Threat card slides in from the right (animation)
   - Show the threat details:
     - Severity badge (LOW/MEDIUM/HIGH/CRITICAL)
     - Confidence percentage
     - Threat type
     - MITRE ATT&CK technique
   - Point out the real-time update

2. **Metrics Update**
   - "Events Detected" counter increments
   - "Auto-Executed" may increment if GREEN action

**What to Say:**
> "I've started the demo mode, which simulates realistic security threats. As you can see, the first threat has been detected - a low-priority port scan. Notice how the threat card animates in, and the metrics update in real-time. The system is using our Isolation Forest ML model to detect anomalies in network traffic."

---

### Minute 2-3: Medium-Priority Threat & RAG Analysis

**Action:**
- Wait for medium-priority threat (API Abuse or Suspicious Login)

**What to Show:**
1. **Threat Analysis**
   - Click "View Details" on the threat card
   - Show the Threat Detail page:
     - **AI Reasoning Chain**: Step-by-step analysis
     - **Retrieved Context**: RAG citations from MITRE ATT&CK
     - **Confidence Breakdown**: Multi-factor scoring
     - **Action Recommendations**: Traffic light system

2. **RAG Context**
   - Point out the retrieved MITRE techniques
   - Explain how the system uses vector search to find relevant threat intelligence
   - Show the similarity scores

**What to Say:**
> "For this medium-priority threat, the system has activated our Threat Intelligence Agent, which uses RAG - Retrieval Augmented Generation - to find relevant context from our knowledge base. You can see it retrieved MITRE ATT&CK techniques and CVE information. The LLM then synthesizes this information to provide a human-readable explanation."

---

### Minute 3-4: High-Priority Threat & Action Classification

**Action:**
- Wait for high-priority threat (Credential Stuffing or Data Exfiltration)

**What to Show:**
1. **Action Classification**
   - Show the "Traffic Light" system:
     - 🟢 **GREEN**: Auto-executed (low risk)
     - 🟡 **YELLOW**: Notified (medium risk, may auto-execute)
     - 🔴 **RED**: Requires approval (high risk)

2. **Action Execution**
   - Show executed actions (if any)
   - Show pending actions requiring approval
   - Navigate to Actions page to show approval workflow

**What to Say:**
> "This high-priority threat triggered our Response Agent, which classified the recommended actions using our traffic light system. Green actions are automatically executed - these are low-risk, reversible actions like logging or rate limiting. Yellow actions may auto-execute based on confidence. Red actions - like blocking an IP or disabling a user - require human approval to ensure we don't accidentally block legitimate traffic."

---

### Minute 4-5: Critical Threat & Full Pipeline

**Action:**
- Wait for critical threat (Privilege Escalation or Insider Threat)

**What to Show:**
1. **Complete Pipeline**
   - Show all agents working together:
     - Detection → Analysis → Response → Execution
   - Point out the timeline in the threat detail

2. **Multiple Threats**
   - Show that the system can handle multiple simultaneous threats
   - Show the threat feed updating in real-time

3. **Summary Stats**
   - Show final metrics:
     - Total threats detected
     - High-priority count
     - Auto-executed actions
     - Pending approvals

**What to Say:**
> "This critical threat demonstrates the full pipeline in action. The system detected an anomaly, retrieved relevant threat intelligence, analyzed the context using our LLM, classified the appropriate response actions, and executed safe actions automatically while queuing high-risk actions for approval. The system can handle multiple threats simultaneously, and all actions are logged and can be rolled back if needed."

---

## Post-Demo: Additional Features

### Compliance Reporting

1. Navigate to **Compliance** page
2. Select report type (SOC2, GDPR, or HIPAA)
3. Generate a report
4. Show the LLM-generated report with metrics and findings

**What to Say:**
> "AutoSec AI also automates compliance reporting. The system aggregates metrics from all detected threats and actions, then uses our LLM to generate human-readable compliance reports that can be used for audits."

### Analytics Dashboard

1. Navigate to **Analytics** page
2. Show threat trends over time
3. Show threat type breakdown
4. Show confidence distribution

**What to Say:**
> "The analytics dashboard provides insights into threat patterns, helping security teams understand attack trends and optimize detection thresholds."

---

## Troubleshooting

### Issue: No threats appearing

**Check:**
1. Is the backend server running?
2. Is the agent trained? (Check `/api/v1/agent/status`)
3. Is the simulation running? (Check simulation status)
4. Are there WebSocket connection errors in browser console?

**Fix:**
```bash
# Check backend logs
# Restart backend if needed
# Check WebSocket connection in browser DevTools
```

### Issue: Threats not saving to database

**Check:**
1. Database file exists: `data/security_logs.db`
2. Database permissions
3. Backend logs for errors

**Fix:**
```bash
# Check database
sqlite3 data/security_logs.db "SELECT COUNT(*) FROM threats;"
```

### Issue: Frontend not updating

**Check:**
1. WebSocket connection status
2. Browser console for errors
3. Network tab for WebSocket messages

**Fix:**
- Refresh the page
- Check WebSocket URL in `frontend/src/services/websocket.ts`
- Verify CORS settings in backend

### Issue: LLM not working

**Check:**
1. `OPENAI_API_KEY` environment variable set
2. API key is valid
3. Backend logs for LLM errors

**Fix:**
```bash
# Set API key
export OPENAI_API_KEY=your_key_here
# Or add to .env file
```

---

## Demo Tips

1. **Practice First**: Run through the demo at least once before presenting
2. **Have Backup**: If something breaks, explain the architecture and show code
3. **Emphasize Safety**: Always mention sandbox mode and approval workflows
4. **Show Real Data**: Point out that threats use realistic IPs, ports, and patterns
5. **Explain AI**: Don't just show features - explain how AI agents work together
6. **Time Management**: Stick to 5 minutes for the main demo, then Q&A

---

## Key Talking Points

### Architecture
- Multi-agent system with specialized roles
- ML-based anomaly detection (Isolation Forest)
- RAG for contextual threat intelligence
- LLM for human-readable explanations
- Traffic light system for safe autonomous actions

### Safety
- All actions in sandbox mode
- High-risk actions require approval
- Rollback capability for all actions
- Comprehensive logging and audit trail

### Scalability
- Handles multiple simultaneous threats
- Real-time processing via WebSocket
- Efficient vector search for RAG
- Batch processing capabilities

### Compliance
- Automated report generation
- Audit trail for all actions
- Metrics aggregation
- LLM-powered report writing

---

## Success Criteria

A successful demo should demonstrate:
- ✅ Real-time threat detection
- ✅ AI-powered threat analysis (RAG + LLM)
- ✅ Autonomous action execution (with safety)
- ✅ Human-in-the-loop approval workflow
- ✅ Multiple threat types and severities
- ✅ System handling multiple simultaneous threats
- ✅ Compliance reporting capabilities

---

## Next Steps After Demo

1. **Q&A Session**: Be prepared to answer:
   - How does the ML model work?
   - How accurate is the detection?
   - What happens in production?
   - How do you handle false positives?
   - Can it integrate with existing security tools?

2. **Technical Deep Dive** (if time permits):
   - Show code structure
   - Explain agent communication
   - Demonstrate RAG retrieval
   - Show action execution logic

3. **Future Roadmap**:
   - Cloud integrations (AWS, GCP, Azure)
   - Reinforcement learning for optimization
   - Graph neural networks for advanced detection
   - Custom threat intelligence feeds

---

## Contact & Resources

- **Documentation**: `docs/` directory
- **API Docs**: `http://localhost:8000/docs`
- **Codebase Walkthrough**: `docs/CODEBASE_WALKTHROUGH.md`
- **Quick Reference**: `docs/QUICK_REFERENCE.md`

