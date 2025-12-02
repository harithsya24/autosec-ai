"""
GCP Security Command Center Integration
Reads security findings from GCP Security Command Center
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta


class GCPSecurityCommandCenterIntegration:
    """Integrate with GCP Security Command Center"""
    
    def __init__(self, project_id: str, credentials_path: Optional[str] = None):
        """
        Initialize GCP Security Command Center integration
        
        Args:
            project_id: GCP project ID
            credentials_path: Path to service account credentials JSON
        """
        self.project_id = project_id
        self.credentials_path = credentials_path
        
        try:
            from google.cloud import securitycenter_v1
            from google.oauth2 import service_account
            
            if credentials_path:
                credentials = service_account.Credentials.from_service_account_file(credentials_path)
                self.client = securitycenter_v1.SecurityCenterClient(credentials=credentials)
            else:
                self.client = securitycenter_v1.SecurityCenterClient()
            
            self.parent = f"organizations/{self._get_organization_id()}"
            print(f" GCP Security Command Center integration initialized (project: {project_id})")
        except ImportError:
            print("  google-cloud-securitycenter not installed. Install with: pip install google-cloud-securitycenter")
            self.client = None
        except Exception as e:
            print(f"  GCP credentials not configured: {e}")
            self.client = None
    
    def _get_organization_id(self) -> str:
        """Get organization ID from project (simplified)"""
        # In production, this would query GCP API
        return "123456789"  # Placeholder
    
    def read_security_findings(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_results: int = 100
    ) -> List[Dict]:
        """
        Read security findings from Security Command Center
        
        Args:
            start_time: Start time for findings
            end_time: End time for findings
            max_results: Maximum number of findings
        
        Returns:
            List of findings in unified format
        """
        if not self.client:
            return []
        
        try:
            from google.cloud.securitycenter_v1 import ListFindingsRequest
            
            if start_time is None:
                start_time = datetime.now() - timedelta(hours=1)
            if end_time is None:
                end_time = datetime.now()
            
            request = ListFindingsRequest(
                parent=self.parent,
                filter=f'state="ACTIVE" AND create_time>="{start_time.isoformat()}"',
                page_size=max_results
            )
            
            findings = self.client.list_findings(request=request)
            
            unified_logs = []
            for finding in findings:
                log_data = self._parse_finding(finding)
                unified_logs.append(log_data)
            
            return unified_logs
        except Exception as e:
            print(f"Error reading GCP Security Command Center findings: {e}")
            return []
    
    def _parse_finding(self, finding) -> Dict:
        """Convert GCP Security Command Center finding to unified format"""
        return {
            'timestamp': finding.create_time.isoformat() if hasattr(finding, 'create_time') else datetime.now().isoformat(),
            'source_ip': finding.source_properties.get('sourceIpAddress', '0.0.0.0') if hasattr(finding, 'source_properties') else '0.0.0.0',
            'user_id': finding.source_properties.get('userName', 'unknown') if hasattr(finding, 'source_properties') else 'unknown',
            'action': finding.category if hasattr(finding, 'category') else 'security_finding',
            'resource': finding.resource_name if hasattr(finding, 'resource_name') else '/',
            'status': 'suspicious',
            'metadata': {
                'finding_id': finding.name if hasattr(finding, 'name') else '',
                'severity': finding.severity if hasattr(finding, 'severity') else 'MEDIUM',
                'category': finding.category if hasattr(finding, 'category') else '',
            }
        }


if __name__ == "__main__":
    # Example usage
    print("GCP Security Command Center Integration")
    print("=" * 50)
    
    # Initialize (requires GCP credentials)
    gcp = GCPSecurityCommandCenterIntegration(project_id='my-project-id')
    
    if gcp.client:
        print("\nReading security findings...")
        findings = gcp.read_security_findings(max_results=10)
        print(f"Retrieved {len(findings)} security findings")




