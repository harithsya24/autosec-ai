"""
AWS CloudWatch Integration
Reads logs from AWS CloudWatch and CloudTrail
"""

import boto3
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json


class CloudWatchIntegration:
    """Integrate with AWS CloudWatch Logs and CloudTrail"""
    
    def __init__(self, region: str = 'us-east-1', profile: Optional[str] = None):
        """
        Initialize CloudWatch integration
        
        Args:
            region: AWS region
            profile: AWS profile name (optional)
        """
        self.region = region
        self.profile = profile
        
        # Initialize clients
        try:
            if profile:
                session = boto3.Session(profile_name=profile)
                self.logs_client = session.client('logs', region_name=region)
                self.cloudtrail_client = session.client('cloudtrail', region_name=region)
            else:
                self.logs_client = boto3.client('logs', region_name=region)
                self.cloudtrail_client = boto3.client('cloudtrail', region_name=region)
            
            print(f"AWS CloudWatch integration initialized (region: {region})")
        except Exception as e:
            print(f"WARNING: AWS credentials not configured: {e}")
            self.logs_client = None
            self.cloudtrail_client = None
    
    def read_cloudwatch_logs(
        self,
        log_group: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Read logs from CloudWatch Logs
        
        Args:
            log_group: CloudWatch log group name
            start_time: Start time for log retrieval
            end_time: End time for log retrieval
            limit: Maximum number of log events
        
        Returns:
            List of log events in unified format
        """
        if not self.logs_client:
            return []
        
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        if end_time is None:
            end_time = datetime.now()
        
        try:
            response = self.logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=int(start_time.timestamp() * 1000),
                endTime=int(end_time.timestamp() * 1000),
                limit=limit
            )
            
            unified_logs = []
            for event in response.get('events', []):
                log_data = self._parse_cloudwatch_event(event)
                unified_logs.append(log_data)
            
            return unified_logs
        except Exception as e:
            print(f"Error reading CloudWatch logs: {e}")
            return []
    
    def read_cloudtrail_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_results: int = 100
    ) -> List[Dict]:
        """
        Read events from CloudTrail
        
        Args:
            start_time: Start time for event retrieval
            end_time: End time for event retrieval
            max_results: Maximum number of events
        
        Returns:
            List of CloudTrail events in unified format
        """
        if not self.cloudtrail_client:
            return []
        
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        if end_time is None:
            end_time = datetime.now()
        
        try:
            response = self.cloudtrail_client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=max_results
            )
            
            unified_logs = []
            for event in response.get('Events', []):
                log_data = self._parse_cloudtrail_event(event)
                unified_logs.append(log_data)
            
            return unified_logs
        except Exception as e:
            print(f"Error reading CloudTrail events: {e}")
            return []
    
    def _parse_cloudwatch_event(self, event: Dict) -> Dict:
        """Convert CloudWatch log event to unified format"""
        message = event.get('message', '{}')
        try:
            log_data = json.loads(message)
        except:
            log_data = {'raw_message': message}
        
        return {
            'timestamp': datetime.fromtimestamp(event.get('timestamp', 0) / 1000).isoformat(),
            'source_ip': log_data.get('sourceIPAddress', '0.0.0.0'),
            'user_id': log_data.get('userIdentity', {}).get('userName', 'unknown'),
            'action': log_data.get('eventName', 'unknown'),
            'resource': log_data.get('requestParameters', {}).get('resource', '/'),
            'status': 'success' if log_data.get('responseElements', {}).get('statusCode') == 200 else 'failed',
            'metadata': log_data
        }
    
    def _parse_cloudtrail_event(self, event: Dict) -> Dict:
        """Convert CloudTrail event to unified format"""
        cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
        
        return {
            'timestamp': event.get('EventTime', datetime.now()).isoformat(),
            'source_ip': cloud_trail_event.get('sourceIPAddress', '0.0.0.0'),
            'user_id': cloud_trail_event.get('userIdentity', {}).get('userName', 'unknown'),
            'action': cloud_trail_event.get('eventName', 'unknown'),
            'resource': cloud_trail_event.get('requestParameters', {}).get('resource', '/'),
            'status': 'success' if cloud_trail_event.get('responseElements', {}).get('statusCode') == 200 else 'failed',
            'metadata': cloud_trail_event
        }


if __name__ == "__main__":
    # Example usage
    print("AWS CloudWatch Integration")
    print("=" * 50)
    
    # Initialize (requires AWS credentials)
    cw = CloudWatchIntegration(region='us-east-1')
    
    if cw.logs_client:
        print("\nReading CloudWatch logs...")
        logs = cw.read_cloudwatch_logs('my-log-group', limit=10)
        print(f"Retrieved {len(logs)} log events")
    
    if cw.cloudtrail_client:
        print("\nReading CloudTrail events...")
        events = cw.read_cloudtrail_events(max_results=10)
        print(f"Retrieved {len(events)} CloudTrail events")


