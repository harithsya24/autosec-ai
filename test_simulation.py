#!/usr/bin/env python3
"""
Quick test script for threat simulation
Tests if simulation is working end-to-end
"""

import sys
import asyncio
from pathlib import Path

# Add paths
sys.path.append(str(Path(__file__).parent))
sys.path.append(str(Path(__file__).parent / "backend" / "api"))

from backend.simulation.threat_simulator import ThreatSimulator, ThreatType

async def test_callback(threat_result):
    #Test callback function
    print(f"Threat Type: {threat_result.get('threat_analysis', {}).get('threat_type')}")
    print(f"Severity: {threat_result.get('anomaly', {}).get('severity')}")
    print(f"Confidence: {threat_result.get('threat_analysis', {}).get('confidence'):.2%}")
    print(f"Alert ID: {threat_result.get('alert_id', 'N/A')}")

async def main():
    print("Testing Threat Simulator...")
    simulator = ThreatSimulator(
        orchestrator=None,
        on_threat_detected=test_callback
    )
    
    print("\n1. Testing single threat generation...")
    result = await simulator.simulate_threat(ThreatType.BRUTE_FORCE)
    
    if result.get("threat_detected"):
        print(" Threat generated successfully!")
        print(f"  - Type: {result.get('threat_analysis', {}).get('threat_type')}")
        print(f"  - Severity: {result.get('anomaly', {}).get('severity')}")
        print(f"  - Confidence: {result.get('threat_analysis', {}).get('confidence'):.2%}")
    else:
        print(" Threat generation failed!")
        return
    
    print("\n2. Testing demo mode (will run for 10 seconds)...")
    await simulator.start_demo_mode(duration_minutes=0.17)  # 10 seconds
    
    await asyncio.sleep(12)
    
    await simulator.stop_simulation()
    
    print(f"\n3. Results:")
    print(f"  - Total threats generated: {len(simulator.generated_threats)}")
    print(f"  - Demo mode: {simulator.demo_mode}")
    print(f"  - Is running: {simulator.is_running}")
    
    if len(simulator.generated_threats) > 0:
        print("\n Demo mode working!")
    else:
        print("\n Demo mode did not generate threats")
    
    print("\nTest complete!")

if __name__ == "__main__":
    asyncio.run(main())


