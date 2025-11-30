"""
Response Agent
Recommends mitigation actions based on threat analysis with traffic light system
"""

from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum


class ActionTier(str, Enum):
    """Traffic light system for action risk levels"""
    GREEN = "green"      # Auto-execute (zero risk)
    YELLOW = "yellow"    # Auto-execute + notify (minimal, reversible)
    RED = "red"          # Require approval (moderate-high risk)


class ResponseAgent:
    """
    AI Agent that recommends mitigation actions
    
    Implements the "Traffic Light" system:
    - 🟢 GREEN: Safe actions (log, alert, monitor)
    - 🟡 YELLOW: Low-risk actions (rate-limit, flag)
    - 🔴 RED: High-risk actions (lock account, block IP)
    """
    
    def __init__(self, sandbox_mode: bool = True):
        """
        Initialize Response Agent
        
        Args:
            sandbox_mode: If True, actions are logged but not executed
        """
        self.sandbox_mode = sandbox_mode
    
    def recommend_actions(
        self,
        threat_analysis: Dict,
        anomaly: Dict
    ) -> Dict:
        """
        Recommend mitigation actions based on threat analysis
        
        Args:
            threat_analysis: Output from ThreatIntelligenceAgent
            anomaly: Original detected anomaly
            
        Returns:
            Dictionary with recommended actions by tier
        """
        confidence = threat_analysis.get("confidence", 0.5)
        severity = threat_analysis.get("severity", "medium")
        threat_type = threat_analysis.get("threat_type", "unknown")
        
        # Determine action tiers
        green_actions = self._get_green_actions(threat_analysis, anomaly)
        yellow_actions = self._get_yellow_actions(threat_analysis, anomaly, confidence, severity)
        red_actions = self._get_red_actions(threat_analysis, anomaly, confidence, severity)
        
        return {
            "actions": {
                "green": green_actions,
                "yellow": yellow_actions,
                "red": red_actions
            },
            "summary": {
                "total_actions": len(green_actions) + len(yellow_actions) + len(red_actions),
                "auto_executable": len(green_actions) + len(yellow_actions),
                "requires_approval": len(red_actions),
                "recommended_priority": self._get_priority(severity, confidence)
            },
            "execution_status": {
                "sandbox_mode": self.sandbox_mode,
                "green_executed": self._should_auto_execute(green_actions),
                "yellow_executed": self._should_auto_execute(yellow_actions) and confidence > 0.7,
                "red_requires_approval": len(red_actions) > 0
            },
            "generated_at": datetime.now().isoformat()
        }
    
    def _get_green_actions(
        self,
        threat_analysis: Dict,
        anomaly: Dict
    ) -> List[Dict]:
        """Get 🟢 GREEN tier actions (always safe to auto-execute)"""
        actions = []
        
        # Always log the event
        actions.append({
            "id": f"action_log_{datetime.now().timestamp()}",
            "type": "log_event",
            "description": "Log security event to database",
            "tier": ActionTier.GREEN,
            "impact": "None",
            "rollback": "N/A",
            "auto_execute": True
        })
        
        # Send alert notification
        actions.append({
            "id": f"action_alert_{datetime.now().timestamp()}",
            "type": "send_alert",
            "description": f"Send alert to SOC team: {threat_analysis.get('threat_type', 'threat')} detected",
            "tier": ActionTier.GREEN,
            "impact": "None",
            "rollback": "N/A",
            "auto_execute": True,
            "channels": ["email", "slack"]
        })
        
        # Create incident ticket
        actions.append({
            "id": f"action_ticket_{datetime.now().timestamp()}",
            "type": "create_ticket",
            "description": "Create incident ticket in ticketing system",
            "tier": ActionTier.GREEN,
            "impact": "None",
            "rollback": "N/A",
            "auto_execute": True
        })
        
        # Increase monitoring
        actions.append({
            "id": f"action_monitor_{datetime.now().timestamp()}",
            "type": "increase_monitoring",
            "description": f"Increase monitoring for source IP: {anomaly.get('source_ip', 'unknown')}",
            "tier": ActionTier.GREEN,
            "impact": "Minimal (slight increase in log volume)",
            "rollback": "Automatic after 24 hours",
            "auto_execute": True,
            "duration": "24h"
        })
        
        return actions
    
    def _get_yellow_actions(
        self,
        threat_analysis: Dict,
        anomaly: Dict,
        confidence: float,
        severity: str
    ) -> List[Dict]:
        """Get 🟡 YELLOW tier actions (low risk, reversible)"""
        actions = []
        
        # Only recommend yellow actions if confidence is reasonable
        if confidence < 0.6:
            return actions
        
        source_ip = anomaly.get("source_ip", "")
        threat_type = threat_analysis.get("threat_type", "")
        
        # Rate-limit suspicious IP (temporary)
        if severity in ["medium", "high", "critical"]:
            actions.append({
                "id": f"action_rate_limit_{datetime.now().timestamp()}",
                "type": "rate_limit_ip",
                "description": f"Rate-limit requests from {source_ip} for 5 minutes",
                "tier": ActionTier.YELLOW,
                "impact": "Legitimate users from this IP may experience slower response",
                "rollback": "Auto-expires in 5 minutes or manual override",
                "auto_execute": confidence > 0.7,
                "duration": "5m",
                "parameters": {
                    "ip": source_ip,
                    "requests_per_minute": 10
                }
            })
        
        # Flag account for review
        user_id = anomaly.get("user_id")
        if user_id and threat_type in ["credential_stuffing", "privilege_escalation"]:
            actions.append({
                "id": f"action_flag_account_{datetime.now().timestamp()}",
                "type": "flag_account",
                "description": f"Flag account {user_id} for security review",
                "tier": ActionTier.YELLOW,
                "impact": "Account flagged in system (no access restriction)",
                "rollback": "Manual unflag required",
                "auto_execute": confidence > 0.75,
                "parameters": {
                    "user_id": user_id,
                    "reason": threat_type
                }
            })
        
        # Trigger additional authentication checks
        if threat_type == "credential_stuffing":
            actions.append({
                "id": f"action_auth_check_{datetime.now().timestamp()}",
                "type": "trigger_auth_check",
                "description": "Require additional authentication (CAPTCHA, MFA challenge)",
                "tier": ActionTier.YELLOW,
                "impact": "Users may need to complete additional verification",
                "rollback": "Automatic after 1 hour",
                "auto_execute": confidence > 0.7,
                "duration": "1h"
            })
        
        return actions
    
    def _get_red_actions(
        self,
        threat_analysis: Dict,
        anomaly: Dict,
        confidence: float,
        severity: str
    ) -> List[Dict]:
        """Get 🔴 RED tier actions (require human approval)"""
        actions = []
        
        # Only recommend red actions for high confidence + high severity
        if confidence < 0.8 or severity not in ["high", "critical"]:
            return actions
        
        source_ip = anomaly.get("source_ip", "")
        user_id = anomaly.get("user_id")
        threat_type = threat_analysis.get("threat_type", "")
        
        # Temporary account lock
        if user_id and threat_type in ["credential_stuffing", "privilege_escalation"]:
            actions.append({
                "id": f"action_lock_account_{datetime.now().timestamp()}",
                "type": "lock_account",
                "description": f"Temporarily lock account {user_id} for 30 minutes",
                "tier": ActionTier.RED,
                "impact": "User cannot log in (could be false positive)",
                "rollback": "Manual unlock via admin panel",
                "auto_execute": False,
                "requires_approval": True,
                "duration": "30m",
                "parameters": {
                    "user_id": user_id,
                    "reason": f"{threat_type} detected with {confidence:.0%} confidence"
                }
            })
        
        # Block IP address (temporary)
        if severity == "critical":
            actions.append({
                "id": f"action_block_ip_{datetime.now().timestamp()}",
                "type": "block_ip",
                "description": f"Block IP address {source_ip} for 1 hour",
                "tier": ActionTier.RED,
                "impact": "All traffic from this IP will be blocked",
                "rollback": "Manual unblock required",
                "auto_execute": False,
                "requires_approval": True,
                "duration": "1h",
                "parameters": {
                    "ip": source_ip,
                    "reason": "Critical threat detected"
                }
            })
        
        # Revoke API tokens
        if threat_type == "privilege_escalation" and user_id:
            actions.append({
                "id": f"action_revoke_tokens_{datetime.now().timestamp()}",
                "type": "revoke_api_tokens",
                "description": f"Revoke all API tokens for {user_id}",
                "tier": ActionTier.RED,
                "impact": "User will need to regenerate API tokens",
                "rollback": "Tokens cannot be restored (user must regenerate)",
                "auto_execute": False,
                "requires_approval": True,
                "parameters": {
                    "user_id": user_id
                }
            })
        
        return actions
    
    def _get_priority(self, severity: str, confidence: float) -> str:
        """Determine overall priority"""
        if severity == "critical" and confidence > 0.8:
            return "P0 - Immediate"
        elif severity in ["high", "critical"]:
            return "P1 - High"
        elif severity == "medium":
            return "P2 - Medium"
        else:
            return "P3 - Low"
    
    def _should_auto_execute(self, actions: List[Dict]) -> bool:
        """Check if actions should be auto-executed"""
        if not actions:
            return False
        return all(action.get("auto_execute", False) for action in actions)
    
    def execute_action(self, action: Dict) -> Dict:
        """
        Execute a single action (in sandbox mode, just logs it)
        
        Args:
            action: Action dictionary
            
        Returns:
            Execution result
        """
        if self.sandbox_mode:
            return {
                "action_id": action.get("id"),
                "status": "logged",
                "message": f"Action logged (sandbox mode): {action.get('description')}",
                "executed_at": datetime.now().isoformat(),
                "sandbox": True
            }
        else:
            # In production, this would actually execute the action
            # For MVP, we'll just log it
            return {
                "action_id": action.get("id"),
                "status": "executed",
                "message": f"Action executed: {action.get('description')}",
                "executed_at": datetime.now().isoformat(),
                "sandbox": False
            }


if __name__ == "__main__":
    """Test the Response Agent"""
    print("🎯 Testing Response Agent...")
    
    agent = ResponseAgent(sandbox_mode=True)
    
    # Sample threat analysis
    threat_analysis = {
        "threat_type": "credential_stuffing",
        "confidence": 0.85,
        "severity": "high",
        "explanation": "Multiple failed login attempts detected",
        "matched_techniques": ["T1078"],
        "recommendations": ["Enable rate limiting", "Review authentication logs"]
    }
    
    # Sample anomaly
    anomaly = {
        "action": "login",
        "status": "failed",
        "source_ip": "203.45.67.89",
        "user_id": "user_123",
        "severity": "high",
        "anomaly_score": -0.75
    }
    
    # Get recommendations
    recommendations = agent.recommend_actions(threat_analysis, anomaly)
    
    print("\n📋 Recommended Actions:")
    print(f"\n🟢 GREEN ({len(recommendations['actions']['green'])} actions):")
    for action in recommendations['actions']['green']:
        print(f"  ✓ {action['description']}")
    
    print(f"\n🟡 YELLOW ({len(recommendations['actions']['yellow'])} actions):")
    for action in recommendations['actions']['yellow']:
        status = "✓ Auto" if action.get('auto_execute') else "⏸ Manual"
        print(f"  {status} {action['description']}")
    
    print(f"\n🔴 RED ({len(recommendations['actions']['red'])} actions):")
    for action in recommendations['actions']['red']:
        print(f"  ⏸ {action['description']} (REQUIRES APPROVAL)")
    
    print(f"\n📊 Summary:")
    print(f"  Total Actions: {recommendations['summary']['total_actions']}")
    print(f"  Auto-Executable: {recommendations['summary']['auto_executable']}")
    print(f"  Requires Approval: {recommendations['summary']['requires_approval']}")
    print(f"  Priority: {recommendations['summary']['recommended_priority']}")
    
    print("\n✓ Response Agent test complete!")

