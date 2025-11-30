"""
Action Executor Agent
Executes mitigation actions based on traffic light system
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from enum import Enum
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

try:
    from backend.utils.database import SecurityLogDatabase
except ImportError:
    from utils.database import SecurityLogDatabase


class ActionStatus(str, Enum):
    """Status of an action"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    APPROVED = "approved"
    REJECTED = "rejected"


class ActionExecutor:
    """
    Executes mitigation actions based on traffic light system
    
    Handles:
    - 🟢 GREEN: Auto-execute immediately
    - 🟡 YELLOW: Auto-execute + notify
    - 🔴 RED: Queue for approval
    """
    
    def __init__(self, db: Optional[SecurityLogDatabase] = None, sandbox_mode: bool = True):
        """
        Initialize Action Executor
        
        Args:
            db: Database instance for tracking actions
            sandbox_mode: If True, actions are logged but not executed
        """
        self.db = db or SecurityLogDatabase()
        self.sandbox_mode = sandbox_mode
        self.active_actions = {}  # Track active actions (rate limits, locks, etc.)
        
        # Initialize action tracking table
        self._init_action_tables()
    
    def _init_action_tables(self):
        """Initialize database tables for action tracking"""
        import sqlite3
        conn = sqlite3.connect(self.db.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        # Actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT UNIQUE NOT NULL,
                action_type TEXT NOT NULL,
                tier TEXT NOT NULL,
                status TEXT NOT NULL,
                threat_alert_id INTEGER,
                description TEXT,
                parameters JSON,
                executed_at DATETIME,
                completed_at DATETIME,
                expires_at DATETIME,
                rollback_info JSON,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_alert_id) REFERENCES alerts(id)
            )
        ''')
        
        # Action approvals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS action_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                approver TEXT,
                decision TEXT NOT NULL,
                reason TEXT,
                approved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (action_id) REFERENCES actions(action_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_tier ON actions(tier)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_action_id ON actions(action_id)')
        
        conn.commit()
        conn.close()
    
    def _get_connection(self):
        """Get database connection (helper method)"""
        import sqlite3
        # Add timeout to handle database locking
        conn = sqlite3.connect(
            self.db.db_path, 
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10.0  # 10 second timeout
        )
        return conn
    
    def execute_action(self, action: Dict, threat_alert_id: Optional[int] = None) -> Dict:
        """
        Execute a single action
        
        Args:
            action: Action dictionary from ResponseAgent
            threat_alert_id: Optional alert ID this action is responding to
            
        Returns:
            Execution result with status and details
        """
        action_id = action.get("id")
        action_type = action.get("type")
        tier = action.get("tier", "green")
        auto_execute = action.get("auto_execute", False)
        
        # Track action in database
        action_record = self._create_action_record(
            action_id, action_type, tier, action, threat_alert_id
        )
        
        # Handle based on tier
        if tier == "green" or (tier == "yellow" and auto_execute):
            # Auto-execute
            return self._execute_action_internal(action, action_record)
        elif tier == "red":
            # Queue for approval
            return self._queue_for_approval(action, action_record)
        else:
            # Yellow but not auto-execute
            return {
                "action_id": action_id,
                "status": ActionStatus.PENDING,
                "message": "Action requires manual review",
                "tier": tier,
                "sandbox": self.sandbox_mode
            }
    
    def _create_action_record(
        self,
        action_id: str,
        action_type: str,
        tier: str,
        action: Dict,
        threat_alert_id: Optional[int]
    ) -> int:
        """Create action record in database"""
        # Calculate expiration if duration specified
        expires_at = None
        if action.get("duration"):
            duration_str = action.get("duration", "")
            expires_at = self._parse_duration(duration_str)
        
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO actions
                (action_id, action_type, tier, status, threat_alert_id, description, 
                 parameters, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action_id,
                action_type,
                tier,
                ActionStatus.PENDING,
                threat_alert_id,
                action.get("description"),
                json.dumps(action.get("parameters", {})),
                expires_at,
                datetime.now()
            ))
            
            conn.commit()
            record_id = cursor.lastrowid
            return record_id
        finally:
            conn.close()
    
    def _execute_action_internal(self, action: Dict, action_record_id: int) -> Dict:
        """Internal method to execute an action"""
        action_id = action.get("id")
        action_type = action.get("type")
        
        # Update status to executing
        self._update_action_status(action_id, ActionStatus.EXECUTING)
        
        try:
            # Route to appropriate executor
            if action_type == "log_event":
                result = self._execute_log_event(action)
            elif action_type == "send_alert":
                result = self._execute_send_alert(action)
            elif action_type == "create_ticket":
                result = self._execute_create_ticket(action)
            elif action_type == "increase_monitoring":
                result = self._execute_increase_monitoring(action)
            elif action_type == "rate_limit_ip":
                result = self._execute_rate_limit_ip(action)
            elif action_type == "flag_account":
                result = self._execute_flag_account(action)
            elif action_type == "trigger_auth_check":
                result = self._execute_trigger_auth_check(action)
            elif action_type == "lock_account":
                result = self._execute_lock_account(action)
            elif action_type == "block_ip":
                result = self._execute_block_ip(action)
            elif action_type == "revoke_api_tokens":
                result = self._execute_revoke_tokens(action)
            else:
                raise ValueError(f"Unknown action type: {action_type}")
            
            # Update status to completed
            self._update_action_status(action_id, ActionStatus.COMPLETED, result)
            
            return {
                "action_id": action_id,
                "status": ActionStatus.COMPLETED,
                "message": result.get("message", "Action executed successfully"),
                "executed_at": datetime.now().isoformat(),
                "sandbox": self.sandbox_mode,
                "details": result
            }
            
        except Exception as e:
            # Update status to failed
            self._update_action_status(action_id, ActionStatus.FAILED, error=str(e))
            
            return {
                "action_id": action_id,
                "status": ActionStatus.FAILED,
                "message": f"Action execution failed: {str(e)}",
                "executed_at": datetime.now().isoformat(),
                "sandbox": self.sandbox_mode,
                "error": str(e)
            }
    
    def _queue_for_approval(self, action: Dict, action_record_id: int) -> Dict:
        """Queue a red-tier action for approval"""
        action_id = action.get("id")
        
        return {
            "action_id": action_id,
            "status": ActionStatus.PENDING,
            "message": "Action queued for approval",
            "tier": "red",
            "requires_approval": True,
            "queued_at": datetime.now().isoformat(),
            "sandbox": self.sandbox_mode
        }
    
    # ============================================================================
    # Action Executors (🟢 GREEN Tier)
    # ============================================================================
    
    def _execute_log_event(self, action: Dict) -> Dict:
        """Execute log event action"""
        if self.sandbox_mode:
            return {
                "message": "Event logged (sandbox mode)",
                "logged": True
            }
        # In production, would log to actual logging system
        return {"message": "Event logged", "logged": True}
    
    def _execute_send_alert(self, action: Dict) -> Dict:
        """Execute send alert action"""
        channels = action.get("channels", ["email"])
        
        if self.sandbox_mode:
            return {
                "message": f"Alert sent to {', '.join(channels)} (sandbox mode)",
                "channels": channels,
                "sent": True
            }
        # In production, would send actual alerts
        return {"message": f"Alert sent to {', '.join(channels)}", "channels": channels}
    
    def _execute_create_ticket(self, action: Dict) -> Dict:
        """Execute create ticket action"""
        if self.sandbox_mode:
            return {
                "message": "Ticket created (sandbox mode)",
                "ticket_id": f"TICKET_{datetime.now().timestamp()}",
                "created": True
            }
        # In production, would create actual ticket
        return {"message": "Ticket created", "ticket_id": "TICKET_123"}
    
    def _execute_increase_monitoring(self, action: Dict) -> Dict:
        """Execute increase monitoring action"""
        duration = action.get("duration", "24h")
        target = action.get("parameters", {}).get("source_ip", "unknown")
        
        if self.sandbox_mode:
            return {
                "message": f"Monitoring increased for {target} (sandbox mode)",
                "target": target,
                "duration": duration,
                "active": True
            }
        # In production, would configure monitoring
        return {"message": f"Monitoring increased for {target}", "target": target}
    
    # ============================================================================
    # Action Executors (🟡 YELLOW Tier)
    # ============================================================================
    
    def _execute_rate_limit_ip(self, action: Dict) -> Dict:
        """Execute rate limit IP action"""
        params = action.get("parameters", {})
        ip = params.get("ip", "unknown")
        duration = action.get("duration", "5m")
        expires_at = self._parse_duration(duration)
        
        # Store active rate limit
        self.active_actions[f"rate_limit_{ip}"] = {
            "type": "rate_limit",
            "ip": ip,
            "expires_at": expires_at,
            "created_at": datetime.now()
        }
        
        if self.sandbox_mode:
            return {
                "message": f"Rate limit applied to {ip} (sandbox mode)",
                "ip": ip,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "active": True
            }
        # In production, would configure rate limiting
        return {"message": f"Rate limit applied to {ip}", "ip": ip}
    
    def _execute_flag_account(self, action: Dict) -> Dict:
        """Execute flag account action"""
        params = action.get("parameters", {})
        user_id = params.get("user_id", "unknown")
        reason = params.get("reason", "security_review")
        
        # Store flagged account
        self.active_actions[f"flagged_{user_id}"] = {
            "type": "flag",
            "user_id": user_id,
            "reason": reason,
            "created_at": datetime.now()
        }
        
        if self.sandbox_mode:
            return {
                "message": f"Account {user_id} flagged (sandbox mode)",
                "user_id": user_id,
                "reason": reason,
                "flagged": True
            }
        # In production, would flag in user system
        return {"message": f"Account {user_id} flagged", "user_id": user_id}
    
    def _execute_trigger_auth_check(self, action: Dict) -> Dict:
        """Execute trigger auth check action"""
        duration = action.get("duration", "1h")
        
        if self.sandbox_mode:
            return {
                "message": "Additional auth checks enabled (sandbox mode)",
                "duration": duration,
                "active": True
            }
        # In production, would configure auth checks
        return {"message": "Additional auth checks enabled", "duration": duration}
    
    # ============================================================================
    # Action Executors (🔴 RED Tier)
    # ============================================================================
    
    def _execute_lock_account(self, action: Dict) -> Dict:
        """Execute lock account action (requires approval)"""
        params = action.get("parameters", {})
        user_id = params.get("user_id", "unknown")
        duration = action.get("duration", "30m")
        expires_at = self._parse_duration(duration)
        
        # Store locked account
        self.active_actions[f"locked_{user_id}"] = {
            "type": "lock",
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": datetime.now()
        }
        
        if self.sandbox_mode:
            return {
                "message": f"Account {user_id} locked (sandbox mode)",
                "user_id": user_id,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "locked": True
            }
        # In production, would lock account
        return {"message": f"Account {user_id} locked", "user_id": user_id}
    
    def _execute_block_ip(self, action: Dict) -> Dict:
        """Execute block IP action (requires approval)"""
        params = action.get("parameters", {})
        ip = params.get("ip", "unknown")
        duration = action.get("duration", "1h")
        expires_at = self._parse_duration(duration)
        
        # Store blocked IP
        self.active_actions[f"blocked_{ip}"] = {
            "type": "block",
            "ip": ip,
            "expires_at": expires_at,
            "created_at": datetime.now()
        }
        
        if self.sandbox_mode:
            return {
                "message": f"IP {ip} blocked (sandbox mode)",
                "ip": ip,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "blocked": True
            }
        # In production, would block IP
        return {"message": f"IP {ip} blocked", "ip": ip}
    
    def _execute_revoke_tokens(self, action: Dict) -> Dict:
        """Execute revoke tokens action (requires approval)"""
        params = action.get("parameters", {})
        user_id = params.get("user_id", "unknown")
        
        if self.sandbox_mode:
            return {
                "message": f"API tokens revoked for {user_id} (sandbox mode)",
                "user_id": user_id,
                "revoked": True
            }
        # In production, would revoke tokens
        return {"message": f"API tokens revoked for {user_id}", "user_id": user_id}
    
    # ============================================================================
    # Utility Methods
    # ============================================================================
    
    def _update_action_status(
        self,
        action_id: str,
        status: ActionStatus,
        result: Optional[Dict] = None,
        error: Optional[str] = None
    ):
        """Update action status in database"""
        update_fields = ["status = ?"]
        values = [status.value]
        
        if status == ActionStatus.COMPLETED:
            update_fields.append("completed_at = ?")
            values.append(datetime.now())
            if result:
                update_fields.append("rollback_info = ?")
                values.append(json.dumps(result))
        elif status == ActionStatus.EXECUTING:
            update_fields.append("executed_at = ?")
            values.append(datetime.now())
        elif status == ActionStatus.FAILED:
            if error:
                update_fields.append("error_message = ?")
                values.append(error)
        
        values.append(action_id)
        
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE actions SET {', '.join(update_fields)} WHERE action_id = ?",
                values
            )
            conn.commit()
        finally:
            conn.close()
    
    def _parse_duration(self, duration_str: str) -> Optional[datetime]:
        """Parse duration string (e.g., '5m', '1h', '24h') to expiration datetime"""
        if not duration_str:
            return None
        
        try:
            # Extract number and unit
            if duration_str.endswith('m'):
                minutes = int(duration_str[:-1])
                return datetime.now() + timedelta(minutes=minutes)
            elif duration_str.endswith('h'):
                hours = int(duration_str[:-1])
                return datetime.now() + timedelta(hours=hours)
            elif duration_str.endswith('d'):
                days = int(duration_str[:-1])
                return datetime.now() + timedelta(days=days)
        except:
            pass
        
        return None
    
    def approve_action(self, action_id: str, approver: str, reason: Optional[str] = None) -> Dict:
        """Approve a pending red-tier action"""
        # Get action
        conn = self._get_connection()
        try:
            conn.row_factory = lambda cursor, row: {
                col[0]: row[idx] for idx, col in enumerate(cursor.description)
            }
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
            action = cursor.fetchone()
            
            if not action:
                return {"status": "error", "message": "Action not found"}
            
            if action['status'] != ActionStatus.PENDING:
                return {"status": "error", "message": f"Action is {action['status']}, cannot approve"}
            
            # Record approval
            cursor.execute('''
                INSERT INTO action_approvals (action_id, approver, decision, reason)
                VALUES (?, ?, ?, ?)
            ''', (action_id, approver, "approved", reason))
            
            conn.commit()
        finally:
            conn.close()
        
        # Update action status (uses its own connection)
        self._update_action_status(action_id, ActionStatus.APPROVED)
        
        # Execute the action
        action_dict = {
            "id": action_id,
            "type": action['action_type'],
            "tier": action['tier'],
            "description": action['description'],
            "parameters": json.loads(action['parameters'] or '{}'),
            "duration": None  # Would parse from expires_at
        }
        
        result = self._execute_action_internal(action_dict, action['id'])
        
        return {
            "status": "approved",
            "action_id": action_id,
            "execution_result": result
        }
    
    def reject_action(self, action_id: str, approver: str, reason: Optional[str] = None) -> Dict:
        """Reject a pending red-tier action"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Record rejection
            cursor.execute('''
                INSERT INTO action_approvals (action_id, approver, decision, reason)
                VALUES (?, ?, ?, ?)
            ''', (action_id, approver, "rejected", reason))
            
            conn.commit()
        finally:
            conn.close()
        
        # Update action status (uses its own connection)
        self._update_action_status(action_id, ActionStatus.REJECTED)
        
        return {
            "status": "rejected",
            "action_id": action_id,
            "message": "Action rejected"
        }
    
    def get_pending_actions(self) -> List[Dict]:
        """Get all pending actions requiring approval"""
        conn = self._get_connection()
        try:
            conn.row_factory = lambda cursor, row: {
                col[0]: row[idx] for idx, col in enumerate(cursor.description)
            }
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM actions
                WHERE status = ? AND tier = ?
                ORDER BY created_at DESC
            ''', (ActionStatus.PENDING, "red"))
            
            actions = cursor.fetchall()
            
            # Convert JSON fields
            for action in actions:
                if action.get('parameters'):
                    action['parameters'] = json.loads(action['parameters'])
            
            return actions
        finally:
            conn.close()
    
    def get_action_history(self, limit: int = 50) -> List[Dict]:
        """Get action execution history"""
        conn = self._get_connection()
        try:
            conn.row_factory = lambda cursor, row: {
                col[0]: row[idx] for idx, col in enumerate(cursor.description)
            }
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM actions
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            
            actions = cursor.fetchall()
            
            # Convert JSON fields
            for action in actions:
                if action.get('parameters'):
                    action['parameters'] = json.loads(action['parameters'])
                if action.get('rollback_info'):
                    action['rollback_info'] = json.loads(action['rollback_info'])
            
            return actions
        finally:
            conn.close()
    
    def rollback_action(self, action_id: str, reason: Optional[str] = None) -> Dict:
        """
        Rollback a completed action
        
        Args:
            action_id: ID of the action to rollback
            reason: Optional reason for rollback
            
        Returns:
            Rollback result
        """
        # Get action
        conn = self._get_connection()
        try:
            conn.row_factory = lambda cursor, row: {
                col[0]: row[idx] for idx, col in enumerate(cursor.description)
            }
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,))
            action = cursor.fetchone()
            
            if not action:
                return {"status": "error", "message": "Action not found"}
            
            if action['status'] != ActionStatus.COMPLETED:
                return {
                    "status": "error",
                    "message": f"Cannot rollback action with status: {action['status']}"
                }
            
            # Check if action is rollbackable
            action_type = action['action_type']
            rollbackable_types = [
                "rate_limit_ip", "flag_account", "lock_account", 
                "block_ip", "trigger_auth_check", "increase_monitoring"
            ]
            
            if action_type not in rollbackable_types:
                return {
                    "status": "error",
                    "message": f"Action type '{action_type}' does not support rollback"
                }
        finally:
            conn.close()
        
        # Execute rollback based on action type
        try:
            if action_type == "rate_limit_ip":
                result = self._rollback_rate_limit(action)
            elif action_type == "flag_account":
                result = self._rollback_flag_account(action)
            elif action_type == "lock_account":
                result = self._rollback_lock_account(action)
            elif action_type == "block_ip":
                result = self._rollback_block_ip(action)
            elif action_type == "trigger_auth_check":
                result = self._rollback_auth_check(action)
            elif action_type == "increase_monitoring":
                result = self._rollback_monitoring(action)
            else:
                result = {"message": "Rollback not implemented for this action type"}
            
            # Update action status
            self._update_action_status(action_id, ActionStatus.ROLLED_BACK)
            
            # Remove from active actions
            params = json.loads(action['parameters'] or '{}')
            if action_type == "rate_limit_ip":
                ip = params.get("ip")
                self.active_actions.pop(f"rate_limit_{ip}", None)
            elif action_type == "flag_account":
                user_id = params.get("user_id")
                self.active_actions.pop(f"flagged_{user_id}", None)
            elif action_type == "lock_account":
                user_id = params.get("user_id")
                self.active_actions.pop(f"locked_{user_id}", None)
            elif action_type == "block_ip":
                ip = params.get("ip")
                self.active_actions.pop(f"blocked_{ip}", None)
            
            conn.close()
            
            return {
                "status": "success",
                "action_id": action_id,
                "message": result.get("message", "Action rolled back successfully"),
                "rolled_back_at": datetime.now().isoformat(),
                "reason": reason
            }
            
        except Exception as e:
            conn.close()
            return {
                "status": "error",
                "message": f"Rollback failed: {str(e)}"
            }
    
    def _rollback_rate_limit(self, action: Dict) -> Dict:
        """Rollback rate limit action"""
        params = json.loads(action.get('parameters', '{}'))
        ip = params.get("ip", "unknown")
        
        if self.sandbox_mode:
            return {"message": f"Rate limit removed for {ip} (sandbox mode)"}
        # In production, would remove rate limit
        return {"message": f"Rate limit removed for {ip}"}
    
    def _rollback_flag_account(self, action: Dict) -> Dict:
        """Rollback flag account action"""
        params = json.loads(action.get('parameters', '{}'))
        user_id = params.get("user_id", "unknown")
        
        if self.sandbox_mode:
            return {"message": f"Flag removed from account {user_id} (sandbox mode)"}
        # In production, would unflag account
        return {"message": f"Flag removed from account {user_id}"}
    
    def _rollback_lock_account(self, action: Dict) -> Dict:
        """Rollback lock account action"""
        params = json.loads(action.get('parameters', '{}'))
        user_id = params.get("user_id", "unknown")
        
        if self.sandbox_mode:
            return {"message": f"Account {user_id} unlocked (sandbox mode)"}
        # In production, would unlock account
        return {"message": f"Account {user_id} unlocked"}
    
    def _rollback_block_ip(self, action: Dict) -> Dict:
        """Rollback block IP action"""
        params = json.loads(action.get('parameters', '{}'))
        ip = params.get("ip", "unknown")
        
        if self.sandbox_mode:
            return {"message": f"IP {ip} unblocked (sandbox mode)"}
        # In production, would unblock IP
        return {"message": f"IP {ip} unblocked"}
    
    def _rollback_auth_check(self, action: Dict) -> Dict:
        """Rollback auth check action"""
        if self.sandbox_mode:
            return {"message": "Additional auth checks disabled (sandbox mode)"}
        # In production, would disable auth checks
        return {"message": "Additional auth checks disabled"}
    
    def _rollback_monitoring(self, action: Dict) -> Dict:
        """Rollback monitoring increase"""
        params = json.loads(action.get('parameters', '{}'))
        target = params.get("source_ip", "unknown")
        
        if self.sandbox_mode:
            return {"message": f"Monitoring restored to normal for {target} (sandbox mode)"}
        # In production, would restore monitoring
        return {"message": f"Monitoring restored to normal for {target}"}


if __name__ == "__main__":
    """Test the Action Executor"""
    print("⚡ Testing Action Executor...")
    
    executor = ActionExecutor(sandbox_mode=True)
    
    # Test green action
    green_action = {
        "id": "test_green_001",
        "type": "log_event",
        "tier": "green",
        "description": "Log security event",
        "auto_execute": True
    }
    
    print("\n🟢 Testing GREEN action...")
    result = executor.execute_action(green_action)
    print(f"  Status: {result['status']}")
    print(f"  Message: {result['message']}")
    
    # Test yellow action
    yellow_action = {
        "id": "test_yellow_001",
        "type": "rate_limit_ip",
        "tier": "yellow",
        "description": "Rate limit IP",
        "auto_execute": True,
        "duration": "5m",
        "parameters": {"ip": "203.45.67.89"}
    }
    
    print("\n🟡 Testing YELLOW action...")
    result = executor.execute_action(yellow_action)
    print(f"  Status: {result['status']}")
    print(f"  Message: {result['message']}")
    
    # Test red action (queued)
    red_action = {
        "id": "test_red_001",
        "type": "lock_account",
        "tier": "red",
        "description": "Lock account",
        "auto_execute": False,
        "duration": "30m",
        "parameters": {"user_id": "user_123"}
    }
    
    print("\n🔴 Testing RED action (queued)...")
    result = executor.execute_action(red_action)
    print(f"  Status: {result['status']}")
    print(f"  Requires Approval: {result.get('requires_approval', False)}")
    
    # Test approval
    print("\n✅ Testing approval...")
    approval_result = executor.approve_action("test_red_001", "admin_user", "High confidence threat")
    print(f"  Status: {approval_result['status']}")
    
    # Get pending actions
    print("\n📋 Pending actions:")
    pending = executor.get_pending_actions()
    print(f"  Count: {len(pending)}")
    
    print("\n✓ Action Executor test complete!")

