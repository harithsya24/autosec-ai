"""
Azure Sentinel Integration
Reads security alerts from Azure Sentinel
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta


class AzureSentinelIntegration:
    """Integrate with Azure Sentinel"""
    
    def __init__(self, subscription_id: str, resource_group: str, workspace_name: str):
        """
        Initialize Azure Sentinel integration
        
        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            workspace_name: Log Analytics workspace name
        """
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.securityinsight import SecurityInsights
            
            self.credential = DefaultAzureCredential()
            self.client = SecurityInsights(self.credential, subscription_id)
            
            print(f" Azure Sentinel integration initialized (workspace: {workspace_name})")
        except ImportError:
            print("  azure-mgmt-securityinsight not installed. Install with: pip install azure-mgmt-securityinsight azure-identity")
            self.client = None
        except Exception as e:
            print(f"  Azure credentials not configured: {e}")
            self.client = None
    
    def read_security_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_results: int = 100
    ) -> List[Dict]:
        """
        Read security alerts from Azure Sentinel
        
        Args:
            start_time: Start time for alerts
            end_time: End time for alerts
            max_results: Maximum number of alerts
        
        Returns:
            List of alerts in unified format
        """
        if not self.client:
            return []
        
        try:
            if start_time is None:
                start_time = datetime.now() - timedelta(hours=1)
            if end_time is None:
                end_time = datetime.now()
            
            # Query Azure Sentinel alerts
            alerts = self.client.incidents.list(
                resource_group_name=self.resource_group,
                workspace_name=self.workspace_name
            )
            
            unified_logs = []
            count = 0
            for alert in alerts:
                if count >= max_results:
                    break
                
                log_data = self._parse_alert(alert)
                unified_logs.append(log_data)
                count += 1
            
            return unified_logs
        except Exception as e:
            print(f"Error reading Azure Sentinel alerts: {e}")
            return []
    
    def _parse_alert(self, alert) -> Dict:
        """Convert Azure Sentinel alert to unified format"""
        return {
            'timestamp': alert.created_time_utc.isoformat() if hasattr(alert, 'created_time_utc') else datetime.now().isoformat(),
            'source_ip': alert.properties.get('source_ip', '0.0.0.0') if hasattr(alert, 'properties') else '0.0.0.0',
            'user_id': alert.properties.get('user_name', 'unknown') if hasattr(alert, 'properties') else 'unknown',
            'action': alert.properties.get('alert_type', 'security_alert') if hasattr(alert, 'properties') else 'security_alert',
            'resource': alert.properties.get('resource_name', '/') if hasattr(alert, 'properties') else '/',
            'status': 'suspicious',
            'metadata': {
                'alert_id': alert.name if hasattr(alert, 'name') else '',
                'severity': alert.properties.get('severity', 'Medium') if hasattr(alert, 'properties') else 'Medium',
                'status': alert.properties.get('status', 'New') if hasattr(alert, 'properties') else 'New',
            }
        }


if __name__ == "__main__":
    # Example usage
    print("Azure Sentinel Integration")
    print("=" * 50)
    
    # Initialize (requires Azure credentials)
    azure = AzureSentinelIntegration(
        subscription_id='your-subscription-id',
        resource_group='your-resource-group',
        workspace_name='your-workspace'
    )
    
    if azure.client:
        print("\nReading security alerts...")
        alerts = azure.read_security_alerts(max_results=10)
        print(f"Retrieved {len(alerts)} security alerts")


