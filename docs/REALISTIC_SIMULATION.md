# Realistic Threat Simulation

## Overview

The threat simulation system now works through the **real log ingestion pipeline**, making it look exactly like a real system is attached to the application.

## How It Works

### Real Pipeline Flow

```
┌─────────────────────────────────────────────────────────┐
│  1. Generate Realistic Log Entry                       │
│     - Threat-specific attributes                        │
│     - Realistic IPs, ports, protocols                  │
│     - CICIDS-style network features                    │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  2. Log Ingestion (Like Real System)                    │
│     - Preprocess log (LogPreprocessor)                  │
│     - Store in database (SecurityLogDatabase)            │
│     - Log appears in logs table                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  3. Threat Detection (Like Real System)                 │
│     - Orchestrator analyzes log                         │
│     - ML model detects anomalies                        │
│     - RAG retrieves threat intelligence                 │
│     - LLM explains the threat                          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  4. Threat Response (Like Real System)                  │
│     - Response agent classifies actions                 │
│     - Actions executed (sandbox mode)                   │
│     - Threat saved to threats table                     │
│     - WebSocket broadcast to frontend                   │
└─────────────────────────────────────────────────────────┘
```

## Key Differences from Before

### Before (Direct Injection)
- Threats were directly created
- Bypassed log ingestion
- Didn't go through preprocessing
- Not stored in logs table

### Now (Real Pipeline)
- ✅ Logs are generated realistically
- ✅ Go through normal log ingestion
- ✅ Preprocessed like real logs
- ✅ Stored in logs table first
- ✅ Analyzed through orchestrator
- ✅ Detected naturally by ML model
- ✅ Full pipeline execution

## What You'll See

### Backend Console Output

When a threat is simulated, you'll see:

```
⏱️  [0s] Demo: Ingesting threat log - Privilege Escalation
  Log ingested (ID: 12345) - privilege_escalation
  ✓ Threat detected through ML pipeline: privilege_escalation (severity: critical)
🔔 Threat detected: Privilege Escalation (severity: critical)
  Saved to database: sim_1234567890.123
  Broadcast via WebSocket: sim_1234567890.123
```

### Database

You'll see entries in:
- **`logs` table**: The original log entry (like real system)
- **`threats` table**: The detected threat with full analysis
- **`alerts` table**: Alert records
- **`actions` table**: Action execution records

### Frontend

- Threats appear in real-time via WebSocket
- Full threat details available
- Actions shown with proper tiers
- Timeline shows detection flow

## Benefits

1. **Realistic**: Mimics actual system behavior
2. **Testable**: Tests the full pipeline
3. **Debuggable**: Can trace through entire flow
4. **Demonstrable**: Shows how real system would work
5. **Complete**: All components are exercised

## Configuration

The simulation still supports:
- Demo mode (5-minute pre-planned sequence)
- Continuous mode (configurable intervals)
- Single threat generation
- Custom threat types

But now all threats go through the real pipeline!

## Example: What Happens

1. **Log Generated**: 
   ```python
   {
     "source_ip": "203.45.67.89",
     "action": "privilege_escalation",
     "status": "403",
     "Label": "ATTACK",
     ...
   }
   ```

2. **Log Ingested**:
   - Preprocessed by `LogPreprocessor`
   - Stored in `logs` table with ID 12345

3. **Log Analyzed**:
   - Orchestrator receives log
   - ML model detects anomaly
   - RAG retrieves MITRE techniques
   - LLM explains threat

4. **Threat Detected**:
   - Threat saved to `threats` table
   - Actions classified (GREEN/YELLOW/RED)
   - WebSocket broadcast sent

5. **Frontend Updates**:
   - Threat card appears
   - Metrics update
   - Actions shown

## Testing

Run the test script to see the pipeline in action:

```bash
python test_simulation.py
```

You'll see:
- Logs being ingested
- Threats being detected
- Database entries being created
- WebSocket broadcasts

## Troubleshooting

If threats aren't appearing:

1. **Check logs table**: Are logs being ingested?
   ```sql
   SELECT COUNT(*) FROM logs;
   ```

2. **Check orchestrator**: Is it trained?
   ```bash
   curl http://localhost:8000/api/v1/agent/status
   ```

3. **Check backend logs**: Look for ingestion messages
   - Should see "Log ingested (ID: ...)"
   - Should see "Threat detected through ML pipeline"

4. **Check database**: Are threats being saved?
   ```sql
   SELECT COUNT(*) FROM threats;
   ```

## Next Steps

The simulation now works exactly like a real system would. You can:
- Add more realistic log patterns
- Mix benign and attack logs
- Simulate traffic bursts
- Add time-based patterns
- Integrate with real log sources

