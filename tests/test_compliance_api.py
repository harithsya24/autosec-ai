"""
Quick test script for Compliance Reporting API
Run this after starting the backend server
"""

import requests
import json
from datetime import datetime, timedelta

def test_compliance_api():
    """Test the compliance reporting API endpoint"""
    
    base_url = "http://localhost:8000"
    endpoint = f"{base_url}/api/v1/compliance/reports"
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    payload = {
        "type": "soc2",
        "period_start": start_date.strftime("%Y-%m-%d"),
        "period_end": end_date.strftime("%Y-%m-%d")
    }
    
    print("Testing Compliance Reporting API")
    print(f"\nEndpoint: {endpoint}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    print("\nSending request...")
    
    try:
        response = requests.post(endpoint, json=payload, timeout=60)
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\n SUCCESS! Report generated:")
            print(f"   Report ID: {data.get('report_id')}")
            print(f"   Type: {data.get('type')}")
            print(f"   Period: {data.get('period_start')} to {data.get('period_end')}")
            print(f"   Sections: {len(data.get('sections', []))}")
            print(f"   Summary length: {len(data.get('summary', ''))} chars")
            print(f"\n   First section: {data.get('sections', [{}])[0].get('title', 'N/A')}")
            print(f"\n   Full response saved to: compliance_test_response.json")
            
            with open('compliance_test_response.json', 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        else:
            print(f"\n ERROR: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("\n ERROR: Cannot connect to backend server")
        print("   Make sure backend is running: cd backend/api && python main.py")
        return False
    except Exception as e:
        print(f"\n ERROR: {e}")
        return False

if __name__ == "__main__":
    test_compliance_api()


