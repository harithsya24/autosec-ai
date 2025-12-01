# Threat Simulation System - Setup Guide

## Overview

The threat simulation system allows you to generate realistic security threats for demo purposes. It integrates seamlessly with the existing AutoSec AI detection pipeline.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Threat Simulator                                       │
│  - Generates realistic threat logs                      │
│  - 10 threat types (Credential Stuffing, DDoS, etc.)    │
│  - Configurable intervals and threat mix                │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Orchestrator Agent                                     │
│  - Processes simulated threats through full pipeline    │
│  - Detection → RAG → LLM → Response                     │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Database + WebSocket                                   │
│  - Saves threats to database                            │
│  - Broadcasts to frontend in real-time                  │
└─────────────────────────────────────────────────────────┘
```

## Files Created

### Backend

1. **`backend/simulation/threat_simulator.py`**
   - Core simulation engine
   - Threat templates with realistic attributes
   - Demo mode with pre-planned threats
   - Continuous simulation mode

2. **`backend/api/simulation_routes.py`**
   - API endpoints for simulation control
   - `/api/v1/simulation/start` - Start continuous simulation
   - `/api/v1/simulation/start-demo` - Start 5-minute demo
   - `/api/v1/simulation/stop` - Stop simulation
   - `/api/v1/simulation/status` - Get status
   - `/api/v1/simulation/next-threat` - Generate single threat
   - `/api/v1/simulation/config` - Update configuration

### Frontend

1. **`frontend/src/components/SimulationControls.tsx`**
   - UI component for controlling simulation
   - Start/Stop buttons
   - Demo mode button
   - Configuration panel
   - Status display

2. **Updated `frontend/src/pages/Dashboard.tsx`**
   - Integrated simulation controls
   - Added animation for new threats
   - Real-time threat updates

3. **Updated `frontend/src/services/api.ts`**
   - Added `simulationService` with all API methods

## Threat Types

The simulator supports 10 threat types:

1. **Credential Stuffing** (HIGH) - T1078, T1110
2. **Privilege Escalation** (CRITICAL) - T1548, T1055, T1068
3. **Suspicious Login** (MEDIUM) - T1078, T1021
4. **API Abuse** (MEDIUM) - T1071, T1499
5. **Data Exfiltration** (HIGH) - T1041, T1020, T1030
6. **Brute Force** (LOW) - T1110, T1021
7. **Port Scan** (LOW) - T1046, T1040
8. **DDoS** (HIGH) - T1498, T1499
9. **Malware** (HIGH) - T1059, T1204, T1566
10. **Insider Threat** (CRITICAL) - T1078, T1048, T1021

Each threat type includes:
- Realistic IP addresses
- Appropriate ports and protocols
- MITRE ATT&CK technique mappings
- Severity and confidence ranges
- Action tier classification (GREEN/YELLOW/RED)

## Usage

### Starting the System

1. **Start Backend:**
```bash
cd backend/api
python main.py
```

2. **Start Frontend:**
```bash
cd frontend
npm run dev
```

3. **Train Agent (if not already trained):**
```bash
# Use API or script
curl -X POST http://localhost:8000/api/v1/train
```

### Using Simulation Controls

1. **Open Dashboard:**
   - Navigate to `http://localhost:3000`
   - Find "Demo Mode - Threat Simulation" panel

2. **Start Demo Mode:**
   - Click "Start Demo (5 min)" button
   - Demo will run for 5 minutes with 10 pre-planned threats
   - Threats appear at: 0s, 30s, 60s, 90s, 120s, 150s, 180s, 210s, 240s, 270s

3. **Start Continuous Mode:**
   - Click "Start Continuous" button
   - Threats will appear every 45 seconds (configurable)
   - Click "Stop Simulation" to stop

4. **Generate Single Threat:**
   - Click "Generate Next Threat" button
   - Immediately generates one threat

5. **Configure:**
   - Click "Config" button
   - Adjust threat interval (10-300 seconds)
   - Click "Update Config"

### API Usage

```bash
# Start demo mode
curl -X POST http://localhost:8000/api/v1/simulation/start-demo \
  -H "Content-Type: application/json" \
  -d '{"duration_minutes": 5}'

# Start continuous
curl -X POST http://localhost:8000/api/v1/simulation/start

# Stop
curl -X POST http://localhost:8000/api/v1/simulation/stop

# Get status
curl http://localhost:8000/api/v1/simulation/status

# Generate next threat
curl -X POST http://localhost:8000/api/v1/simulation/next-threat

# Update config
curl -X POST http://localhost:8000/api/v1/simulation/config \
  -H "Content-Type: application/json" \
  -d '{"interval_seconds": 30}'
```

## Demo Mode Timeline

Demo mode runs for exactly 5 minutes with this threat sequence:

| Time | Threat Type | Severity | Action Tier |
|------|-------------|----------|-------------|
| 0s | Privilege Escalation | CRITICAL | RED |
| 30s | Insider Threat | CRITICAL | RED |
| 60s | Credential Stuffing | HIGH | RED |
| 90s | Data Exfiltration | HIGH | RED |
| 120s | DDoS | HIGH | RED |
| 150s | Suspicious Login | MEDIUM | YELLOW |
| 180s | API Abuse | MEDIUM | YELLOW |
| 210s | Malware | MEDIUM | YELLOW |
| 240s | Brute Force | LOW | GREEN |
| 270s | Port Scan | LOW | GREEN |

This provides a good mix:
- 2 CRITICAL threats
- 3 HIGH threats
- 3 MEDIUM threats
- 2 LOW threats
- All three action tiers represented

## Integration Points

### With Detection Pipeline

The simulator integrates with the existing detection pipeline:

1. **Log Analyzer**: Simulated threats are processed through the ML model
2. **Threat Intelligence**: RAG retrieval finds relevant MITRE techniques
3. **Response Agent**: Actions are classified using the traffic light system
4. **Action Executor**: Actions are executed (in sandbox mode)

### With Database

All simulated threats are saved to the database:
- `threats` table: Complete threat analysis
- `alerts` table: Alert records
- `actions` table: Action execution records

### With Frontend

Real-time updates via WebSocket:
- New threats appear immediately
- Metrics update automatically
- Action status updates in real-time

## Configuration

### Threat Interval

Control how often threats appear:
- Default: 45 seconds
- Range: 10-300 seconds
- Can be updated via UI or API

### Enabled Threat Types

By default, all threat types are enabled. You can filter specific types via API:

```python
# Enable only high-severity threats
simulator.update_config(
    enabled_threats=[
        ThreatType.CREDENTIAL_STUFFING,
        ThreatType.PRIVILEGE_ESCALATION,
        ThreatType.DATA_EXFILTRATION
    ]
)
```

### Auto-Clear Low Priority

Option to automatically clear low-priority threats after a delay:
- Default: Disabled
- Can enable with `auto_clear_low_priority: true`
- Clear delay: `clear_after_seconds` (default: 120)

## Troubleshooting

### Threats Not Appearing

1. **Check Backend:**
   - Is server running?
   - Check logs for errors
   - Verify agent is trained

2. **Check Simulation Status:**
   ```bash
   curl http://localhost:8000/api/v1/simulation/status
   ```

3. **Check WebSocket:**
   - Open browser DevTools
   - Check WebSocket connection
   - Look for connection errors

### Threats Not Being Detected

1. **Agent Not Trained:**
   - Simulator will still generate threats
   - But they won't be processed through ML
   - Will use template values instead

2. **Check Orchestrator:**
   - Verify orchestrator is initialized
   - Check agent status endpoint

### Frontend Not Updating

1. **WebSocket Connection:**
   - Check connection status in UI
   - Verify WebSocket URL in `websocket.ts`
   - Check CORS settings

2. **Browser Console:**
   - Look for JavaScript errors
   - Check network tab for WebSocket messages

## Best Practices

1. **For Demos:**
   - Use demo mode (5 minutes, pre-planned)
   - Ensures consistent experience
   - Perfect for presentations

2. **For Development:**
   - Use continuous mode
   - Adjust interval to your needs
   - Generate single threats for testing

3. **For Testing:**
   - Use specific threat types
   - Test different severity levels
   - Verify action classification

## Safety

- All actions execute in **sandbox mode**
- No actual network changes
- No production impact
- All threats are clearly labeled as "simulation"

## Next Steps

1. **Customize Threat Types:**
   - Add new threat templates
   - Modify existing templates
   - Adjust confidence ranges

2. **Integrate Real Data:**
   - Use actual CICIDS attack patterns
   - Sample from real threat intelligence
   - Incorporate custom attack scenarios

3. **Advanced Features:**
   - Multi-stage attacks
   - Attack campaigns
   - Time-based patterns
   - Geographic distribution

## Support

- **Documentation**: `docs/demo_script.md` for demo walkthrough
- **API Docs**: `http://localhost:8000/docs`
- **Code**: `backend/simulation/threat_simulator.py`

