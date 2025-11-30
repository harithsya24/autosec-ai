# Real-World Use Case: Network Security Monitoring

## 🎯 Scenario

**Security Operations Center (SOC)** monitoring network traffic in real-time to detect and respond to cyber attacks.

## 📊 Data Source

Using **CICIDS 2017 Dataset** - Real network traffic captures containing:
- **Benign traffic** (Monday) - Normal network activity
- **DDoS attacks** (Friday afternoon) - Distributed Denial of Service
- **Port scans** (Friday afternoon) - Network reconnaissance
- **Web attacks** (Thursday morning) - HTTP-based attacks
- **Infiltration** (Thursday afternoon) - Data exfiltration attempts

## 🔄 Workflow

### Step 1: Baseline Training
1. Load benign traffic from Monday dataset
2. Train anomaly detection model on normal patterns
3. Establish baseline for "normal" network behavior

### Step 2: Real-Time Monitoring
1. Process attack traffic files
2. Convert CICIDS format to unified log schema
3. Analyze each network flow through the AI pipeline:
   - **Log Analyzer**: Detect anomalies using Isolation Forest
   - **Threat Intelligence**: RAG retrieval + LLM analysis
   - **Response Agent**: Recommend mitigation actions
   - **Action Executor**: Execute safe actions automatically

### Step 3: Threat Storage
1. Store detected threats in database
2. Include full analysis, confidence scores, and recommendations
3. Make available via API and dashboard

## 🚀 Running the Use Case

### Prerequisites
1. Backend API running: `cd backend/api && python main.py`
2. Frontend dashboard running: `cd frontend && npm run dev`

### Execute

```bash
# Process real CICIDS attack data
python scripts/process_real_threats.py
```

This will:
- ✅ Train on 15,000 benign records
- ✅ Process 500 attack records from each attack type
- ✅ Detect real threats using AI agents
- ✅ Store threats in database
- ✅ Display summary statistics

### Expected Output

```
🛡️  AutoSec AI - Real Threat Detection Use Case
======================================================================

📊 Scenario: Security Operations Center (SOC)
   Monitoring network traffic for malicious activity
   Processing real CICIDS 2017 attack dataset

🔧 Initializing system...

📚 Step 1: Training on benign traffic (baseline)...
   Loading Monday-WorkingHours-pcap_ISCX.csv...
   Found 15,000 benign records
   Training anomaly detection model...
   ✅ Model trained on benign traffic baseline

🚨 Step 2: Processing real attack traffic...
   Simulating real-time threat detection

   📁 Processing: DDoS Attack
      File: Friday-WorkingHours-Afternoon-DDos-pcap_ISCX.csv
      Found 500 attack records
      ✅ Processed 500 records, detected 450 threats

   📁 Processing: Port Scan Attack
      File: Friday-WorkingHours-Afternoon-PortScan-pcap_ISCX.csv
      Found 500 attack records
      ✅ Processed 500 records, detected 480 threats

   ...

======================================================================
📊 DETECTION SUMMARY
======================================================================
✅ Total threats detected: 1,850
📁 Threats stored in database: 1,850

📈 Threats by type:
   • DDoS Attack: 450
   • Port Scan: 480
   • Web Attack: 420
   • Infiltration: 500

🌐 View threats in dashboard:
   http://localhost:3000

📡 API endpoint:
   GET http://localhost:8000/api/v1/threats
```

## 📱 Viewing Results

### Dashboard
1. Open `http://localhost:3000`
2. Navigate to Dashboard
3. See real threats detected from CICIDS data
4. Click on threats to see detailed analysis

### API
```bash
# Get all threats
curl http://localhost:8000/api/v1/threats

# Get specific threat
curl http://localhost:8000/api/v1/threats/{alert_id}
```

## 🎯 What You'll See

### Real Threat Types
- **DDoS Attacks**: High-volume network flooding
- **Port Scans**: Reconnaissance activity
- **Web Attacks**: HTTP-based exploits
- **Infiltration**: Data exfiltration attempts

### AI Analysis
- Anomaly scores from ML model
- RAG-retrieved threat intelligence
- LLM-generated explanations
- Confidence scores
- MITRE ATT&CK technique matches

### Actions
- Green actions: Auto-executed (logging, alerts)
- Yellow actions: Auto-executed with notification (rate limiting)
- Red actions: Queued for approval (account locks, IP blocks)

## 🔍 Technical Details

### Data Conversion
CICIDS network flow data is converted to unified schema:
- Source/Destination IPs
- Port numbers
- Flow duration
- Packet counts
- Byte counts
- Attack labels

### Detection Pipeline
1. **Feature Extraction**: Network flow metrics
2. **Anomaly Detection**: Isolation Forest model
3. **Threat Analysis**: RAG + LLM reasoning
4. **Action Recommendation**: Traffic light system
5. **Execution**: Autonomous or approval-based

## 📈 Performance

- **Processing Speed**: ~100 records/second
- **Detection Accuracy**: Based on trained model
- **False Positive Rate**: Depends on model tuning
- **Response Time**: < 3 seconds per threat analysis

## 🎓 Learning Outcomes

This use case demonstrates:
- Real-world threat detection
- AI-powered security analysis
- Autonomous response capabilities
- Enterprise-ready dashboard
- Complete audit trail

---

**Ready to run?** Execute `python scripts/process_real_threats.py` and watch real threats appear in your dashboard!


