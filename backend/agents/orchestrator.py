"""
Orchestrator Agent
Coordinates the workflow: Detection -> RAG -> LLM -> Response
"""

from typing import Dict, List, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import agents (handle both absolute and relative imports)
try:
    from backend.agents.log_analyzer import LogAnalyzerAgent
    from backend.agents.threat_intelligence_agent import ThreatIntelligenceAgent
    from backend.agents.response_agent import ResponseAgent
    from backend.agents.action_executor import ActionExecutor
    from rag.vector_store.chroma_setup import ThreatIntelligenceRAG
except ImportError:
    # Fallback for relative imports
    from .log_analyzer import LogAnalyzerAgent
    from .threat_intelligence_agent import ThreatIntelligenceAgent
    from .response_agent import ResponseAgent
    from .action_executor import ActionExecutor
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from rag.vector_store.chroma_setup import ThreatIntelligenceRAG


class OrchestratorAgent:
    """
    Main orchestrator that coordinates all agents
    
    Workflow:
    1. Log Analyzer Agent: Detect anomalies
    2. Threat Intelligence Agent: Explain threats (RAG + LLM)
    3. Response Agent: Recommend actions
    4. Return complete analysis
    """
    
    def __init__(
        self,
        log_analyzer: Optional[LogAnalyzerAgent] = None,
        threat_intel: Optional[ThreatIntelligenceAgent] = None,
        response_agent: Optional[ResponseAgent] = None,
        action_executor: Optional[ActionExecutor] = None,
        sandbox_mode: bool = True
    ):
        """
        Initialize Orchestrator
        
        Args:
            log_analyzer: LogAnalyzerAgent instance (creates new if None)
            threat_intel: ThreatIntelligenceAgent instance (creates new if None)
            response_agent: ResponseAgent instance (creates new if None)
            action_executor: ActionExecutor instance (creates new if None)
            sandbox_mode: Enable sandbox mode for actions
        """
        self.log_analyzer = log_analyzer or LogAnalyzerAgent()
        self.response_agent = response_agent or ResponseAgent(sandbox_mode=sandbox_mode)
        self.action_executor = action_executor or ActionExecutor(sandbox_mode=sandbox_mode)
        
        # Initialize RAG if not provided
        if threat_intel is None:
            rag = ThreatIntelligenceRAG()
            self.threat_intel = ThreatIntelligenceAgent(rag=rag)
        else:
            self.threat_intel = threat_intel
        
        self.sandbox_mode = sandbox_mode
    
    def analyze_log(
        self,
        raw_log: Dict,
        return_full_analysis: bool = True
    ) -> Dict:
        """
        Complete analysis pipeline for a single log
        
        Args:
            raw_log: Raw log dictionary
            return_full_analysis: If True, includes RAG + LLM analysis
            
        Returns:
            Complete analysis with detection, explanation, and recommendations
        """
        if not self.log_analyzer.is_trained:
            raise Exception("Log Analyzer not trained! Call train() first.")
        
        # Step 1: Detect anomalies
        anomalies, results_df = self.log_analyzer.detect_anomalies([raw_log])
        
        if not anomalies:
            # No threat detected
            return {
                "threat_detected": False,
                "status": "normal",
                "message": "No threats detected - log appears normal",
                "analyzed_at": datetime.now().isoformat()
            }
        
        anomaly = anomalies[0]
        
        # Step 2: Analyze threat (RAG + LLM)
        if return_full_analysis:
            threat_analysis = self.threat_intel.analyze_threat(anomaly)
        else:
            # Quick mode - skip RAG/LLM
            threat_analysis = {
                "threat_type": "unknown",
                "confidence": abs(anomaly.get("anomaly_score", 0.0)),
                "severity": anomaly.get("severity", "medium"),
                "explanation": f"Anomaly detected with score {anomaly.get('anomaly_score', 0.0):.3f}",
                "matched_techniques": [],
                "recommendations": []
            }
        
        # Step 3: Recommend actions
        action_recommendations = self.response_agent.recommend_actions(
            threat_analysis, anomaly
        )
        
        # Step 4: Execute actions (green and auto-execute yellow)
        executed_actions = []
        pending_actions = []
        
        # Execute green actions
        for action in action_recommendations.get("actions", {}).get("green", []):
            execution_result = self.action_executor.execute_action(action)
            executed_actions.append(execution_result)
        
        # Execute yellow actions (if auto-execute enabled)
        for action in action_recommendations.get("actions", {}).get("yellow", []):
            if action.get("auto_execute", False):
                execution_result = self.action_executor.execute_action(action)
                executed_actions.append(execution_result)
            else:
                pending_actions.append(action)
        
        # Queue red actions for approval
        for action in action_recommendations.get("actions", {}).get("red", []):
            execution_result = self.action_executor.execute_action(action)
            pending_actions.append({
                **action,
                "execution_status": execution_result
            })
        
        # Format actions for frontend
        formatted_executed = []
        for action in executed_actions:
            if isinstance(action, dict):
                formatted_executed.append({
                    "action_id": action.get("action_id", ""),
                    "type": action.get("type", ""),
                    "tier": action.get("tier", "green"),
                    "status": "completed",
                    "description": action.get("description", ""),
                    "parameters": action.get("parameters", {}),
                    "executed_at": action.get("executed_at", datetime.now().isoformat())
                })
        
        formatted_pending = []
        for action in pending_actions:
            if isinstance(action, dict):
                formatted_pending.append({
                    "action_id": action.get("action_id", ""),
                    "type": action.get("type", ""),
                    "tier": action.get("tier", "red"),
                    "status": "pending",
                    "description": action.get("description", ""),
                    "parameters": action.get("parameters", {}),
                    "requires_approval": True
                })
        
        # Combine everything
        return {
            "threat_detected": True,
            "status": "threat_identified",
            "anomaly": {
                "anomaly_score": anomaly.get("anomaly_score"),
                "severity": anomaly.get("severity"),
                "detection_method": anomaly.get("detection_method", "ml-based"),
                "source_ip": anomaly.get("source_ip"),
                "user_id": anomaly.get("user_id"),
                "action": anomaly.get("action"),
                "resource": anomaly.get("resource"),
                "status": anomaly.get("status"),
                "timestamp": anomaly.get("timestamp", datetime.now().isoformat())
            },
            "threat_analysis": {
                **threat_analysis,
                "reasoning_chain": threat_analysis.get("reasoning_chain", []),
                "retrieved_context": threat_analysis.get("retrieved_context", []),
                "confidence_breakdown": threat_analysis.get("confidence_breakdown", {})
            },
            "recommended_actions": action_recommendations,
            "executed_actions": formatted_executed,
            "pending_actions": formatted_pending,
            "timeline": {
                "detected_at": anomaly.get("detected_at", datetime.now().isoformat()),
                "analyzed_at": threat_analysis.get("analyzed_at", datetime.now().isoformat()),
                "recommendations_generated_at": action_recommendations.get("generated_at"),
                "actions_executed_at": datetime.now().isoformat() if executed_actions else None
            },
            "analyzed_at": datetime.now().isoformat()
        }
    
    def analyze_batch(
        self,
        raw_logs: List[Dict],
        return_full_analysis: bool = True
    ) -> Dict:
        """
        Analyze multiple logs in batch
        
        Args:
            raw_logs: List of raw log dictionaries
            return_full_analysis: If True, includes RAG + LLM for each
            
        Returns:
            Batch analysis results
        """
        if not self.log_analyzer.is_trained:
            raise Exception("Log Analyzer not trained! Call train() first.")
        
        # Detect all anomalies
        anomalies, results_df = self.log_analyzer.detect_anomalies(raw_logs)
        
        results = {
            "total_logs": len(raw_logs),
            "anomalies_detected": len(anomalies),
            "detection_rate": len(anomalies) / len(raw_logs) if raw_logs else 0,
            "threats": [],
            "summary": {
                "by_severity": {},
                "by_threat_type": {}
            }
        }
        
        # Analyze each anomaly
        for anomaly in anomalies:
            if return_full_analysis:
                threat_analysis = self.threat_intel.analyze_threat(anomaly)
                action_recommendations = self.response_agent.recommend_actions(
                    threat_analysis, anomaly
                )
            else:
                threat_analysis = {
                    "threat_type": "unknown",
                    "confidence": abs(anomaly.get("anomaly_score", 0.0)),
                    "severity": anomaly.get("severity", "medium")
                }
                action_recommendations = {"summary": {}}
            
            threat_entry = {
                "anomaly": {
                    "anomaly_score": anomaly.get("anomaly_score"),
                    "severity": anomaly.get("severity"),
                    "source_ip": anomaly.get("source_ip"),
                    "action": anomaly.get("action")
                },
                "threat_analysis": threat_analysis,
                "recommended_actions": action_recommendations
            }
            
            results["threats"].append(threat_entry)
            
            # Update summary
            severity = anomaly.get("severity", "unknown")
            results["summary"]["by_severity"][severity] = \
                results["summary"]["by_severity"].get(severity, 0) + 1
            
            threat_type = threat_analysis.get("threat_type", "unknown")
            results["summary"]["by_threat_type"][threat_type] = \
                results["summary"]["by_threat_type"].get(threat_type, 0) + 1
        
        results["analyzed_at"] = datetime.now().isoformat()
        return results
    
    def get_system_status(self) -> Dict:
        """Get status of all agents"""
        return {
            "log_analyzer": {
                "trained": self.log_analyzer.is_trained,
                "model": "Isolation Forest"
            },
            "threat_intelligence": {
                "rag_available": self.threat_intel.rag is not None,
                "llm_enabled": self.threat_intel.use_llm,
                "llm_model": self.threat_intel.llm_model if self.threat_intel.use_llm else None
            },
            "response_agent": {
                "sandbox_mode": self.response_agent.sandbox_mode
            },
            "action_executor": {
                "sandbox_mode": self.action_executor.sandbox_mode,
                "active_actions": len(self.action_executor.active_actions)
            },
            "orchestrator": {
                "status": "ready" if self.log_analyzer.is_trained else "not_ready",
                "sandbox_mode": self.sandbox_mode
            }
        }


if __name__ == "__main__":
    """Test the Orchestrator"""
    print(" Testing Orchestrator Agent...")
    
    # Initialize orchestrator
    orchestrator = OrchestratorAgent(sandbox_mode=True)
    
    # Check status
    status = orchestrator.get_system_status()
    print(f"\n System Status:")
    print(f"  Log Analyzer: {'Trained' if status['log_analyzer']['trained'] else 'Not Trained'}")
    print(f"  Threat Intel: RAG={'Yes' if status['threat_intelligence']['rag_available'] else 'No'}, "
          f"LLM={'Yes' if status['threat_intelligence']['llm_enabled'] else 'No'}")
    print(f"  Sandbox Mode: {'ON' if status['response_agent']['sandbox_mode'] else 'OFF'}")
    
    if not status['log_analyzer']['trained']:
        print("\n  Log Analyzer not trained. Run training first.")
        print("   Example: POST /api/v1/train")
    else:
        # Test with sample log
        sample_log = {
            "Flow Duration": 120.5,
            "Total Fwd Packets": 150,
            "Total Backward Packets": 50,
            "Flow Bytes/s": 1000000,
            "Flow Packets/s": 100,
            "Destination Port": 22,
            "Fwd Packet Length Mean": 1000,
            "Bwd Packet Length Mean": 500,
            "Flow IAT Mean": 1.2,
            "Fwd IAT Mean": 1.0,
            "Bwd IAT Mean": 1.5,
            "Fwd PSH Flags": 1,
            "Bwd PSH Flags": 0,
            "FIN Flag Count": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 10,
            "Average Packet Size": 750,
            "Label": "BENIGN"
        }
        
        print("\n Analyzing sample log...")
        try:
            result = orchestrator.analyze_log(sample_log, return_full_analysis=True)
            
            if result.get("threat_detected"):
                print(f"\n Threat Detected!")
                print(f"  Severity: {result['anomaly']['severity']}")
                print(f"  Threat Type: {result['threat_analysis']['threat_type']}")
                print(f"  Confidence: {result['threat_analysis']['confidence']:.2%}")
                print(f"\n  Explanation:\n  {result['threat_analysis']['explanation']}")
                print(f"\n  Recommended Actions: {result['recommended_actions']['summary']['total_actions']}")
            else:
                print("\n No threats detected")
        except Exception as e:
            print(f"\n Error: {e}")
    
    print("\n Orchestrator test complete!")

