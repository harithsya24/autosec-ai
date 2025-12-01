# Troubleshooting Threat Simulation

## Issue: Demo Not Generating Threats

If the demo is not generating threats, follow these steps:

### 1. Check Backend Logs

When you start the demo, you should see messages like:
```
Starting demo mode for 5 minutes...
Demo mode started - 10 threats planned
Demo: Generating threat at 0s - privilege_escalation
Threat detected callback: Privilege Escalation
  Saved to database: sim_1234567890.123
  Broadcast via WebSocket: sim_1234567890.123
Generated threat: privilege_escalation (severity: critical, confidence: 90.19%)
```

If you don't see these messages, the simulator might not be initialized.

### 2. Check Simulator Status

```bash
curl http://localhost:8000/api/v1/simulation/status
```

Should return:
```json
{
  "status": "ok",
  "is_running": true,
  "demo_mode": true,
  "threats_generated": 1,
  ...
}
```

### 3. Check if Simulator is Initialized

Look for this message when starting the backend:
```
Threat simulator initialized (ready for demo mode)
```

If you see:
```
Warning: Failed to initialize simulator: ...
```

Check the error message and fix the issue.

### 4. Test Simulation Directly

Run the test script:
```bash
python test_simulation.py
```

This will test if the simulator works independently.

### 5. Check WebSocket Connection

In the browser console (F12), check:
- Is WebSocket connected?
- Are there any WebSocket errors?
- Check Network tab for WebSocket messages

### 6. Common Issues

#### Issue: "Simulator not initialized"

**Fix:** Restart the backend server. The simulator is initialized in the startup event.

#### Issue: Threats generated but not appearing in frontend

**Check:**
1. WebSocket connection status
2. Browser console for errors
3. Network tab for WebSocket messages

**Fix:** 
- Refresh the page
- Check WebSocket URL in `frontend/src/services/websocket.ts`
- Verify CORS settings

#### Issue: "Orchestrator not set"

**Fix:** The simulator now works without an orchestrator (uses template-based generation). If you see this message, it's just informational - threats will still be generated.

#### Issue: Database errors

**Check:**
- Database file exists: `data/security_logs.db`
- Database permissions
- Backend logs for specific errors

**Fix:**
```bash
# Check database
sqlite3 data/security_logs.db "SELECT COUNT(*) FROM threats;"
```

### 7. Manual Test

Test the API directly:
```bash
# Start demo
curl -X POST http://localhost:8000/api/v1/simulation/start-demo \
  -H "Content-Type: application/json" \
  -d '{"duration_minutes": 1}'

# Check status
curl http://localhost:8000/api/v1/simulation/status

# Generate single threat
curl -X POST http://localhost:8000/api/v1/simulation/next-threat
```

### 8. Enable Debug Logging

The simulator now includes debug logging. Check backend console for:
- `"Demo: Generating threat at Xs - threat_type"`
- `"Threat detected callback: ..."`
- `"Saved to database: ..."`
- `"Broadcast via WebSocket: ..."`

If you see these messages but threats don't appear:
- Check WebSocket connection
- Check frontend WebSocket handler
- Check browser console for errors

### 9. Verify Frontend Integration

Check that:
1. `SimulationControls` component is rendered on Dashboard
2. WebSocket service is connected
3. Threat cards are being updated

In browser console:
```javascript
// Check WebSocket
console.log(wsService.connected)

// Check threats
console.log(threats)
```

### 10. Reset Everything

If nothing works:
```bash
# Stop backend and frontend
# Clear database (optional)
rm data/security_logs.db

# Restart backend
cd backend/api
python main.py

# Restart frontend
cd frontend
npm run dev

# Start demo from UI
```

## Still Not Working?

1. Check all error messages in backend console
2. Check browser console for frontend errors
3. Verify all files are saved correctly
4. Check that imports are working
5. Test with `test_simulation.py` script

If issues persist, check:
- Python version (3.8+)
- All dependencies installed
- Port 8000 and 3000 are available
- No firewall blocking WebSocket connections

