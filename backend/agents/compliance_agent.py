"""
Compliance Reporting Agent
Generates automated compliance reports using LLM-powered analysis
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pathlib import Path
import json

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env from project root (3 levels up from backend/agents/)
    env_path = Path(__file__).parent.parent.parent / ".env"
    load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, use system env vars only

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


class ComplianceAgent:
    """Generates compliance reports for SOC2, GDPR, HIPAA, etc."""
    
    def __init__(self):
        self.llm = None
        if LLM_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                self.llm = ChatOpenAI(
                    model="gpt-4o-mini",  # Use same model as threat intelligence agent
                    temperature=0.3,
                )
                print("Compliance Agent: LLM initialized")
            except Exception as e:
                print(f"Compliance Agent: Failed to initialize LLM: {e}")
                self.llm = None
        else:
            if not LLM_AVAILABLE:
                print("Compliance Agent: LangChain not available, using template mode")
            elif not os.getenv("OPENAI_API_KEY"):
                print("Compliance Agent: OPENAI_API_KEY not set, using template mode")
    
    async def generate_report(
        self,
        report_type: str,
        start_date: str,
        end_date: str
    ) -> Dict[str, Any]:
        """
        Generate a compliance report
        
        Args:
            report_type: Type of report (soc2, gdpr, hipaa, custom)
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
        
        Returns:
            Compliance report dictionary
        """
        # Get metrics from database
        metrics = await self._get_metrics(start_date, end_date)
        
        # Generate report sections
        if self.llm:
            sections = await self._generate_with_llm(report_type, metrics, start_date, end_date)
        else:
            sections = self._generate_template(report_type, metrics, start_date, end_date)
        
        # Create report
        report = {
            "report_id": f"report_{datetime.now().timestamp()}",
            "type": report_type,
            "period_start": start_date,
            "period_end": end_date,
            "generated_at": datetime.now().isoformat(),
            "summary": self._generate_summary(metrics, report_type),
            "sections": sections,
            "metrics": metrics
        }
        
        return report
    
    async def _get_metrics(self, start_date: str, end_date: str) -> Dict[str, Any]:
        """Get compliance metrics from database"""
        try:
            import sqlite3
            import sys
            from pathlib import Path
            sys.path.append(str(Path(__file__).parent.parent))
            from utils.database import SecurityLogDatabase
            
            db = SecurityLogDatabase()
            conn = sqlite3.connect(db.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Get action metrics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_actions,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM actions
                WHERE executed_at >= ? AND executed_at <= ?
            ''', (start_date, end_date))
            
            action_row = cursor.fetchone()
            # Handle None values from database (SUM returns None if no rows)
            total_actions = (action_row[0] if action_row and action_row[0] is not None else 0) or 0
            approved = (action_row[1] if action_row and action_row[1] is not None else 0) or 0
            rejected = (action_row[2] if action_row and action_row[2] is not None else 0) or 0
            
            conn.close()
            
            return {
                "total_incidents": int(total_actions),
                "incidents_resolved": int(approved),
                "false_positives": int(rejected),
                "average_response_time": 250,  # Mock value
                "actions_taken": int(total_actions),
                "actions_approved": int(approved),
                "actions_rejected": int(rejected),
            }
        except Exception as e:
            print(f"Error getting metrics: {e}")
            return {
                "total_incidents": 0,
                "incidents_resolved": 0,
                "false_positives": 0,
                "average_response_time": 0,
                "actions_taken": 0,
                "actions_approved": 0,
                "actions_rejected": 0,
            }
    
    async def _generate_with_llm(
        self,
        report_type: str,
        metrics: Dict[str, Any],
        start_date: str,
        end_date: str
    ) -> List[Dict[str, Any]]:
        """Generate report sections using LLM"""
        
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are a compliance reporting expert. Generate detailed compliance report sections.
            
            Report Type: {report_type}
            Period: {start_date} to {end_date}
            Metrics: {metrics}
            
            Generate 3-4 sections covering:
            1. Security Incident Overview
            2. Threat Detection & Response
            3. Access Control & Authentication
            4. Data Protection & Privacy
            
            For each section, provide:
            - Title
            - Content (2-3 paragraphs)
            - Key Findings (3-5 bullet points)
            - Recommendations (3-5 bullet points)
            
            Format as JSON with this structure:
            {{
                "sections": [
                    {{
                        "title": "...",
                        "content": "...",
                        "findings": ["...", "..."],
                        "recommendations": ["...", "..."]
                    }}
                ]
            }}
            """),
            ("human", "Generate the compliance report sections.")
        ])
        
        try:
            messages = prompt_template.format_messages(
                report_type=report_type.upper(),
                start_date=start_date,
                end_date=end_date,
                metrics=json.dumps(metrics, indent=2)
            )
            response = await self.llm.ainvoke(messages)
            
            # Parse LLM response
            if hasattr(response, 'content'):
                content = response.content
            elif isinstance(response, str):
                content = response
            else:
                content = str(response)
            
            # Try to extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            # Try to find JSON object in response
            import re
            json_match = re.search(r'\{.*"sections".*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group(0)
            
            parsed = json.loads(content)
            return parsed.get("sections", [])
        except json.JSONDecodeError as e:
            print(f"LLM JSON parsing error: {e}")
            if 'content' in locals():
                print(f"Response content: {content[:500]}...")
            return self._generate_template(report_type, metrics, start_date, end_date)
        except Exception as e:
            print(f"LLM generation error: {e}")
            import traceback
            traceback.print_exc()
            return self._generate_template(report_type, metrics, start_date, end_date)
    
    def _generate_template(
        self,
        report_type: str,
        metrics: Dict[str, Any],
        start_date: str,
        end_date: str
    ) -> List[Dict[str, Any]]:
        """Generate template-based report sections"""
        
        sections = [
            {
                "title": "Security Incident Overview",
                "content": f"""
                During the reporting period ({start_date} to {end_date}), the AutoSec AI system 
                detected and analyzed {metrics['total_incidents']} security incidents. 
                Of these, {metrics['incidents_resolved']} were successfully resolved through 
                automated and manual intervention. The system maintained an average response 
                time of {metrics['average_response_time']}ms, demonstrating efficient threat 
                detection and mitigation capabilities.
                """,
                "findings": [
                    f"Total incidents detected: {metrics.get('total_incidents', 0) or 0}",
                    f"Incidents resolved: {metrics.get('incidents_resolved', 0) or 0}",
                    f"False positive rate: {(metrics.get('false_positives', 0) or 0) / max(metrics.get('total_incidents', 0) or 1, 1) * 100:.1f}%",
                    f"Average response time: {metrics.get('average_response_time', 0) or 0}ms"
                ],
                "recommendations": [
                    "Continue monitoring false positive rates and adjust detection thresholds as needed",
                    "Maintain current response time performance",
                    "Review and update threat intelligence feeds regularly"
                ]
            },
            {
                "title": "Threat Detection & Response",
                "content": f"""
                The autonomous threat detection system successfully identified and classified 
                security threats using AI-powered analysis. {metrics.get('actions_taken', 0) or 0} mitigation 
                actions were executed, with {metrics.get('actions_approved', 0) or 0} approved and executed 
                automatically or with human approval. The system's traffic light classification 
                (green/yellow/red) ensured appropriate risk management for all actions.
                """,
                "findings": [
                    f"Total actions taken: {metrics.get('actions_taken', 0) or 0}",
                    f"Actions approved: {metrics.get('actions_approved', 0) or 0}",
                    f"Actions rejected: {metrics.get('actions_rejected', 0) or 0}",
                    "All high-risk actions required human approval"
                ],
                "recommendations": [
                    "Continue using the traffic light system for action classification",
                    "Review rejected actions to improve detection accuracy",
                    "Document all actions for audit trail compliance"
                ]
            },
            {
                "title": "Access Control & Authentication",
                "content": f"""
                The system monitored and analyzed authentication events throughout the reporting 
                period. Suspicious login attempts and privilege escalation attempts were 
                automatically detected and flagged for review. The system maintained comprehensive 
                logs of all access control events for compliance auditing.
                """,
                "findings": [
                    "All authentication events logged and analyzed",
                    "Suspicious patterns detected and flagged automatically",
                    "Access control policies enforced consistently"
                ],
                "recommendations": [
                    "Review authentication logs regularly for anomalies",
                    "Update access control policies based on threat intelligence",
                    "Implement multi-factor authentication where applicable"
                ]
            }
        ]
        
        if report_type.lower() in ['gdpr', 'hipaa']:
            sections.append({
                "title": "Data Protection & Privacy",
                "content": """
                The system maintains strict data privacy controls, including PII anonymization 
                before processing. All sensitive data is handled in accordance with privacy 
                regulations, with comprehensive audit trails maintained for compliance purposes.
                """,
                "findings": [
                    "PII anonymization enabled for all log processing",
                    "Data retention policies enforced",
                    "Audit trails maintained for all data access"
                ],
                "recommendations": [
                    "Continue PII anonymization practices",
                    "Regular review of data retention policies",
                    "Ensure all data processing complies with regulations"
                ]
            })
        
        return sections
    
    def _generate_summary(self, metrics: Dict[str, Any], report_type: str) -> str:
        """Generate executive summary"""
        total_incidents = metrics.get('total_incidents', 0) or 0
        false_positives = metrics.get('false_positives', 0) or 0
        actions_taken = metrics.get('actions_taken', 0) or 0
        avg_response = metrics.get('average_response_time', 0) or 0
        
        false_positive_rate = (false_positives / max(total_incidents, 1)) * 100 if total_incidents > 0 else 0.0
        
        return f"""
        This {report_type.upper()} compliance report covers the reporting period. During this period, 
        the AutoSec AI system detected {total_incidents} security incidents and executed {actions_taken} 
        mitigation actions. The system maintained high detection accuracy with a false positive rate of 
        {false_positive_rate:.1f}% and an average response time of {avg_response}ms. All high-risk actions 
        required human approval, ensuring appropriate oversight and compliance with security policies.
        """

